from update_firmware import firmware_update
import logging

firmware_update()

log_file = 'output.log'
log_format = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, filename=log_file, filemode='w', format=log_format)