import base64
import getpass
import json
import logging
import os
import polling2
import requests
import sys
import time
import warnings
from datetime import datetime
from pprint import pprint
import urllib3.exceptions
from colorama import Fore, Style
from tabulate import tabulate

warnings.filterwarnings("ignore")
logging.basicConfig(format='%(message)s', stream=sys.stdout, level=logging.INFO)
with open("firmware_info.json") as file:
    firmware_data = json.load(file)

firmware_info = firmware_data["firmware_info"]


def set_iDRAC_script_session(script_examples=""):
    """Function to set iDRAC session used to execute all workflows for this session: pass in iDRAC IP, iDRAC username and iDRAC password. It will also prompt for SSL certificate verification for all Redfish calls and finally prompt to create X-auth token session. By creating X-auth token session, all Redfish calls executed will use this X-auth token session for authentication instead of username/password."""
    global creds
    global x_auth_token
    if script_examples:
        print(
            "\n- IdracRedfishSupport.set_iDRAC_script_session(), this example will prompt the user to input iDRAC IP, iDRAC username, iDRAC password, SSL cert verification and create X-auth token session")
    else:
        x_auth_token = "no"
        creds = {}
        idrac_ip = input(str("- Enter iDRAC IP: "))
        creds["idrac_ip"] = idrac_ip
        idrac_username = input(str("- Enter iDRAC username: "))
        creds["idrac_username"] = idrac_username
        idrac_password = getpass.getpass("- Enter iDRAC %s password: " % idrac_username)
        creds["idrac_password"] = idrac_password
        verify_cert = input(str("- Verify SSL certificate, pass in True to verify or False to ignore: "))
        if verify_cert.lower() == "true":
            creds["verify_cert"] = True
        elif verify_cert.lower() == "false":
            creds["verify_cert"] = False
        else:
            logging.info("- INFO, invalid value entered to verify SSL certificate")
            return
        user_response = input(
            str("- Create iDRAC X-auth token session? Pass in \"y\" for yes or \"n\" for no. Creating iDRAC X-auth token session, all Redfish commands will be executed using this X-auth token for auth instead of username/password: "))
        if user_response.lower() == "y":
            x_auth_token = "yes"
            response = requests.get('https://%s/redfish/v1' % creds["idrac_ip"], verify=creds["verify_cert"],
                                    auth=(creds["idrac_username"], creds["idrac_password"]))
            data = response.json()
            if response.status_code == 401:
                logging.error("\n- ERROR, GET request failed, status code %s returned, check login credentials" % (
                    response.status_code))
                return
            else:
                data = response.json()
            if response.status_code != 200:
                logging.warning(
                    "\n- WARNING, GET request failed to get Redfish version, status code %s returned" % response.status_code)
                return
            else:
                pass
            redfish_version = int(data["RedfishVersion"].replace(".", ""))
            if redfish_version >= 160:
                session_uri = "redfish/v1/SessionService/Sessions"
            elif redfish_version < 160:
                session_uri = "redfish/v1/Sessions"
            else:
                logging.info("- INFO, unable to select URI based off Redfish version")
                return
            url = 'https://%s/%s' % (creds["idrac_ip"], session_uri)
            payload = {"UserName": creds["idrac_username"], "Password": creds["idrac_password"]}
            headers = {'content-type': 'application/json'}
            response = requests.post(url, data=json.dumps(payload), headers=headers, verify=creds["verify_cert"])
            data = response.json()
            if response.status_code == 201:
                logging.info(
                    "\n- PASS, iDRAC X auth token successfully created. X auth sessions URI \"%s\"" % response.headers[
                        "Location"])
            else:
                try:
                    logging.error(
                        "\n- ERROR, unable to create X-auth_token session, status code %s returned, detailed error results:\n %s" % (
                            response.status_code, data))
                except:
                    logging.error("\n- ERROR, unable to create X-auth_token session, status code %s returned" % (
                        response.status_code))
                return
            creds["idrac_x_auth_token"] = response.headers["X-Auth-Token"]
        elif user_response.lower() != "n":
            logging.error("- ERROR, invalid value entered to create iDRAC x-auth token session")
            return


def check_firmware_version(firmware=""):
    """Function to either get current firmware inventory or update firmware for one supported device. Supported function arguments: (get_fw_inventory (possible value: True), firmware_image_path (pass in the complete directory path with firmware image name. Firmware image must be Windows Dell Update Package EXE file) and reboot (supported values: yes and no). Reboot server is required for certain devices to apply the firmware (Examples: BIOS, NIC, PERC). Refer to iDRAC user guide update section for more details."""

    logging.info("\n- INFO, getting current firmware version for iDRAC %s -\n" % creds["idrac_ip"])
    if x_auth_token == "yes":
        response = requests.get(
            'https://%s/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=1)' % creds["idrac_ip"],
            verify=creds["verify_cert"], headers={'X-Auth-Token': creds["idrac_x_auth_token"]})
    else:
        response = requests.get(
            'https://%s/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=1)' % creds["idrac_ip"],
            verify=creds["verify_cert"], auth=(creds["idrac_username"], creds["idrac_password"]))
    if response.status_code == 401:
        logging.error(
            "- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
        return
    elif response.status_code == 200:
        logging.info("- INFO, GET command passed to get firmware inventory")
    else:
        logging.error("\n- FAIL, Command failed to check job status, return code %s" % response.status_code)
        logging.error("Extended Info Message: {0}".format(response.json()))
        return
    inventory = response.json()

    firmware_list = inventory["Members"]
    matching_firmware_data = []
    for all_firmware in firmware_list:
        firmware_id = all_firmware["@odata.id"]
        if firmware in firmware_id:
            matching_firmware_data.append(firmware_id)
    for i in matching_firmware_data:
        if "Installed" in i:
            response2 = requests.get(
                'https://%s%s' % (creds["idrac_ip"], i),
                verify=creds["verify_cert"], auth=(creds["idrac_username"], creds["idrac_password"]))
            inventory2 = response2.json()
            current_firmware_version = inventory2['Version']

            logging.info("Current firmware version is %s", current_firmware_version)
            return current_firmware_version


def firmware_update_multipart_upload(script_examples="", get_fw_inventory="", fw_image_path="", reboot=""):
    """Function to either get current firmware inventory or update firmware for one supported device. Supported function arguments: (get_fw_inventory (possible value: True), firmware_image_path (pass in the complete directory path with firmware image name. Firmware image must be Windows Dell Update Package EXE file) and reboot (supported values: yes and no). Reboot server is required for certain devices to apply the firmware (Examples: BIOS, NIC, PERC). Refer to iDRAC user guide update section for more details."""
    global job_id
    if script_examples:
        print("""\n- IdracRedfishSupport.firmware_update_multipart_upload(fw_image_path="C:\\Users\\administrator\\Downloads\\Diags_R650.EXE"), this example will update DIAGS. This device is an immediate update so no reboot argument is needed.
        \n- IdracRedfishSupport.firmware_update_multipart_upload(fw_image_path="C:\\Users\\administrator\\Downloads\\H745_A16.EXE",reboot="no"), this example shows updating H745 storage controller. Update job is scehduled but will not auto reboot. Update job will execute on next server manual reboot.
        \n- IdracRedfishSupport.firmware_update_multipart_upload(fw_image_path="C:\\Users\\administrator\\Downloads\\H745_A16.EXE",reboot="yes"), this example will reboot the server now to update H745 storage controller.""")
    elif get_fw_inventory:
        logging.info("\n- INFO, getting current firmware inventory for iDRAC %s -\n" % creds["idrac_ip"])
        if x_auth_token == "yes":
            response = requests.get(
                'https://%s/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=1)' % creds["idrac_ip"],
                verify=creds["verify_cert"], headers={'X-Auth-Token': creds["idrac_x_auth_token"]})
        else:
            response = requests.get(
                'https://%s/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=1)' % creds["idrac_ip"],
                verify=creds["verify_cert"], auth=(creds["idrac_username"], creds["idrac_password"]))
        if response.status_code == 401:
            logging.error(
                "- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
            return
        elif response.status_code == 200:
            logging.info("- INFO, GET command passed to get firmware inventory")
        else:
            logging.error("\n- FAIL, Command failed to check job status, return code %s" % response.status_code)
            logging.error("Extended Info Message: {0}".format(response.json()))
            return
        data = response.json()
        for i in data['Members']:
            pprint(i)
            print("\n")
    elif fw_image_path:
        start_time = datetime.now()
        print(
            "\n- INFO, downloading update package to create update job, this may take a few minutes depending on firmware image size")
        url = "https://%s/redfish/v1/UpdateService/MultipartUpload" % creds["idrac_ip"]
        if reboot.lower() == "yes":
            payload = {"Targets": [], "@Redfish.OperationApplyTime": "Immediate", "Oem": {}}
        elif reboot.lower() == "no":
            payload = {"Targets": [], "@Redfish.OperationApplyTime": "OnReset", "Oem": {}}
        else:
            payload = {"Targets": [], "@Redfish.OperationApplyTime": "OnReset", "Oem": {}}
        files = {"UpdateParameters": (None, json.dumps(payload), "application/json"),
                 "UpdateFile": (os.path.basename(fw_image_path), open(fw_image_path, "rb"), "application/octet-stream")}
        if x_auth_token == "yes":
            headers = {'X-Auth-Token': creds["idrac_x_auth_token"]}
            response = requests.post(url, files=files, headers=headers, verify=creds["verify_cert"])
        else:
            response = requests.post(url, files=files, verify=creds["verify_cert"],
                                     auth=(creds["idrac_username"], creds["idrac_password"]))
        if response.status_code == 401:
            logging.error(
                "- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
            return
        elif response.status_code == 202:
            logging.info("- PASS, POST command passed for multipart upload")
        else:
            data = response.json()
            logging.error("- FAIL, status code %s returned, detailed error: %s" % (response.status_code, data))
            return
        try:
            job_id = response.headers['Location'].split("/")[-1]
        except:
            logging.error("- FAIL, unable to locate job ID in header")
            return
        logging.info(
            "- PASS, update job ID %s successfully created, script will now loop polling the job status\n" % job_id)
        retry_count = 1
        while True:
            if retry_count == 20:
                logging.warning("- WARNING, GET command retry count of 20 has been reached, script will exit")
                return
            try:
                if x_auth_token == "yes":
                    response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (creds["idrac_ip"], job_id),
                                            verify=creds["verify_cert"],
                                            headers={'X-Auth-Token': creds["idrac_x_auth_token"]})
                else:
                    response = requests.get('https://%s/redfish/v1/TaskService/Tasks/%s' % (creds["idrac_ip"], job_id),
                                            verify=creds["verify_cert"],
                                            auth=(creds["idrac_username"], creds["idrac_password"]))
            except requests.ConnectionError as error_message:
                logging.info("- INFO, GET request failed due to connection error, retry")
                time.sleep(10)
                retry_count += 1
                continue
            data = response.json()
            if response.status_code == 200 or response.status_code == 202:
                logging.info("- PASS, GET command passed to get job status details")
            else:
                logging.error(
                    "- FAIL, GET command failed to get job ID details, status code %s returned, detailed error: %s" % (
                        response.status_code, data))
                return
            if data["TaskState"] == "Completed":
                logging.info("\n- INFO, job ID marked completed, detailed final job status results:\n")
                for i in data['Oem']['Dell'].items():
                    print("%s: %s" % (i[0], i[1]))
                logging.info("\n- JOB ID %s completed in %s" % (job_id, current_time))
                return
            current_time = str(datetime.now() - start_time)[0:7]
            data = response.json()
            message_string = data["Messages"]
            if str(current_time)[0:7] >= "0:30:00":
                logging.error(
                    "\n- FAIL: Timeout of 30 minutes has been hit, update job should of already been marked completed. Check the iDRAC job queue and LC logs to debug the issue\n")
                return
            elif "failed" in data['Oem']['Dell']['Message'] or "completed with errors" in data['Oem']['Dell'][
                'Message'] or "Failed" in data['Oem']['Dell']['Message']:
                logging.error("- FAIL: Job failed, current message is: %s" % data["Messages"])
                return
            elif "scheduled" in data['Oem']['Dell']['Message']:
                logging.error("- PASS, job ID %s successfully marked as scheduled" % data["Id"])
                if reboot.lower() == "yes":
                    logging.info("- INFO, user selected to reboot the server now to apply the update")
                    loop_job_status_final()
                    return
                elif reboot.lower() == "no":
                    logging.info(
                        "- INFO, user selected to NOT reboot the server now. Update job is still scheduled and will be applied on next manual server reboot")
                    return
                else:
                    logging.warning(
                        "- WARNING, missing reboot argument for rebooting the server. Update job is still scheduled and will be applied on next manual server reboot")
                    return
            elif "completed successfully" in data['Oem']['Dell']['Message']:
                logging.info(
                    "\n- PASS, job ID %s successfully marked completed, detailed final job status results:\n" % data[
                        "Id"])
                for i in data['Oem']['Dell'].items():
                    print("%s: %s" % (i[0], i[1]))
                logging.info("\n- %s completed in: %s" % (job_id, str(current_time)[0:7]))
                break
            else:
                logging.info("- INFO, job status: %s" % message_string[0]["Message"].rstrip("."))
                time.sleep(1)
                continue
    else:
        logging.warning(
            "- WARNING, missing arguments or incorrect argument values passed in. Check help text and script examples for more details")
        return


def loop_job_status_final():
    """Function to loop checking final job status, this function cannot be called individually and is leveraged only by other functions after POST action is executed to create a job ID"""
    start_time = datetime.now()
    while True:
        if x_auth_token == "yes":
            response = requests.get(
                'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/%s' % (creds["idrac_ip"], job_id),
                verify=creds["verify_cert"], headers={'X-Auth-Token': creds["idrac_x_auth_token"]})
        else:
            response = requests.get(
                'https://%s/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/%s' % (creds["idrac_ip"], job_id),
                verify=creds["verify_cert"], auth=(creds["idrac_username"], creds["idrac_password"]))
        current_time = (datetime.now() - start_time)
        if response.status_code == 401:
            logging.error(
                "- ERROR, status code 401 detected, check to make sure your iDRAC script session has correct username/password credentials or if using X-auth token, confirm the session is still active.")
            return
        elif response.status_code != 200:
            logging.error("\n- ERROR, Command failed to check job status, return code is %s" % response.status_code)
            logging.info("Extended Info Message: {0}".format(response.json()))
            return
        data = response.json()
        if str(current_time)[0:7] >= "2:00:00":
            logging.error("\n- ERROR: Timeout of 2 hours has been hit, script stopped\n")
            return
        elif "Fail" in data['Message'] or "fail" in data['Message'] or data['JobState'] == "Failed":
            logging.error("- ERROR, job ID %s failed, final job status message: %s" % (job_id, data['Message']))
            logging.info("- INFO, check iDRAC Lifecycle Logs for more details about the job failure")
            return
        elif "Lifecycle Controller in use" in data["Message"]:
            logging.warning(
                "- WARNING, Lifecycle Controller in use detected, job will start when Lifecycle Controller is available. Check server state to make sure it is out of POST and iDRAC job queue to confirm no jobs are already executing.")
            return
        elif data['JobState'] == "Completed":
            logging.info("\n--- PASS, Final Detailed Job Status Results ---\n")
            for i in data.items():
                if "odata" not in i[0] or "MessageArgs" not in i[0] or "TargetSettingsURI" not in i[0]:
                    print("%s: %s" % (i[0], i[1]))
            break
        else:
            logging.info("- INFO, job status not completed, current status: \"%s\"" % (data['Message'].strip(".")))
            time.sleep(3)


def get_firmware_version(firmware_info, firmware_name):
    for firmware in firmware_info:
        if firmware['firmwareName'] == firmware_name:
            firmware_version = firmware['firmware-version']
            logging.info("Required firmware Version  is : %s " % firmware_version)
            return firmware_version
    return None


def check_all_current_versions():
    table = []

    for firmware in firmware_info:
        try:
            firmware_name = firmware["firmwareName"]
            version = check_firmware_version(firmware=firmware_name)
            table.append([Fore.RED + str(version) + Style.RESET_ALL, Fore.GREEN + firmware_name + Style.RESET_ALL])
        except Exception as exception_msg:
            # Handle the exception here, you can print an error message or perform any other actions
            print(f"Error checking firmware version for {firmware_name}: {str(exception_msg)}")

    table_output = tabulate(table, headers=['Current_version', 'Firmware_name'], tablefmt='grid')
    print(table_output)


def update_all_firmware():
    for firmware in firmware_info:
        try:

            firmware_name = firmware["firmwareName"]
            firmware_version = firmware["firmware-version"]
            firmware_path = firmware["firmware_path"]
            version = check_firmware_version(firmware=firmware_name)
            version_to_check = get_firmware_version(firmware_info=firmware_info, firmware_name=firmware_name)
            if version == version_to_check:
                logging.info("Current version matches the required version.")
            else:
                logging.info("Current version does not match the required version.")
                logging.info("Updating the firmware.")
                try:
                    firmware_update_multipart_upload(fw_image_path=firmware_path, reboot="yes")
                except Exception as exception_msg:
                    logging.info(exception_msg)
                finally:
                    try:

                        polling2.poll(lambda: check_firmware_version(firmware=firmware_name),
                                      step=10, timeout=30,
                                      ignore_exceptions=(urllib3.exceptions.HTTPError,))

                    except polling2.TimeoutException:
                        raise Exception('timeoutException')

        except Exception as exception_msg:
            logging.info(exception_msg)