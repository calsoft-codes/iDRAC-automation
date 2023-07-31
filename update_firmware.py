import json
import polling2
import urllib3
import logging

from Check_version import check_firmware_version, set_iDRAC_script_session, get_firmware_version, \
    firmware_update_multipart_upload, check_all_current_versions, update_all_firmware
from tabulate import tabulate

with open('firmware_info.json', 'r') as json_file:
    data = json.load(json_file)
firmware_info = data['firmware_info']


def firmware_update():
    def update_firmware(option, firmware_path):
        try:
            version = check_firmware_version(firmware=option)
            version_to_check = get_firmware_version(firmware_info=firmware_info, firmware_name=option)
            if version == version_to_check:
                logging.info("Current version matches the required version.")
            else:
                logging.info("Current version does not matches the required version.")
                logging.info("Updating the firmware.")
                try:
                    firmware_update_multipart_upload(fw_image_path=firmware_path, reboot="yes")
                except Exception as exception_msg:
                    logging.info(exception_msg)
                finally:
                    try:
                        polling2.poll(lambda: check_firmware_version(firmware=firmware_name),
                                      step=10, timeout=300,
                                      ignore_exceptions=(urllib3.exceptions.HTTPError,))
                    except polling2.TimeoutException:
                        raise Exception('timeoutException')

        except Exception as exception_msg:
            logging.info(exception_msg)

    table = []
    for i, firmware in enumerate(firmware_info, 1):
        firmware_name = firmware["firmwareName"]
        table.append([i, firmware_name])

    table.append([len(firmware_info) + 1, "Check All Versions"])
    table.append([len(firmware_info) + 2, "Update All firmwares "])
    table.append([len(firmware_info) + 3, "Exit"])

    table_output = tabulate(table, headers=['Option', 'Firmware'], tablefmt='grid')

    set_iDRAC_script_session()

    print(table_output)

    while True:
        # Ask user for the firmware option to update or check all versions
        choice = input("Enter the option number to update firmware (or enter 'all' to check all versions): ")

        # Validate and perform firmware update based on user's choice
        if choice.isdigit():
            choice = int(choice)
            if 1 <= choice <= len(firmware_info):
                selected_firmware = firmware_info[choice - 1]
                selected_firmware_name = selected_firmware["firmwareName"]
                firmware_path = selected_firmware["firmware_path"]
                update_firmware(selected_firmware_name, firmware_path)
            elif choice == len(firmware_info) + 1:
                check_all_current_versions()
            elif choice == len(firmware_info) + 2:
                print("Updating All the firmwares.")
                update_all_firmware()
            elif choice == len(firmware_info) + 3:
                print("Exiting the firmware update.")
                break
            else:
                print("Invalid option!")
        elif choice.lower() == "all":
            check_all_current_versions()
        else:
            print("Invalid input!")

