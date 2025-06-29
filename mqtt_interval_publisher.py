import json
import time
import logging
import paho.mqtt.client as mqtt
import sys
import os # Import the os module for file system operations

# --- Configuration Loading ---
def load_config(config_file="config.json"):
    """
    Loads configuration from a JSON file.
    Provides default values if the file or specific keys are missing.
    """
    default_config = {
        "mqtt_broker": "broker.emqx.io",
        "mqtt_port": 1883,
        "mqtt_topic": "home/status/power",
        "interval_true_false": 5000,  # Time in milliseconds between sending "true" and then "false"
        "interval_false_true": 10000, # Time in milliseconds between sending "false" and then "true"
        "log_file": "mqtt_messages.log",
        "repeats": -1,                # Number of true/false pairs to send. -1 for infinite.
        "true_message": "true",       # Default message for "true" state
        "false_message": "false",     # Default message for "false" state
        "ftp_folder_to_manage": "./ftp_images" # Default path to the FTP folder to manage
    }
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
            # Merge loaded config with defaults to ensure all keys are present
            return {**default_config, **config}
    except FileNotFoundError:
        print(f"Configuration file '{config_file}' not found. Using default configuration.")
        return default_config
    except json.JSONDecodeError:
        print(f"Error decoding JSON from '{config_file}'. Please check JSON syntax (e.g., missing quotes, comments). Using default configuration.")
        return default_config
    except Exception as e:
        print(f"An unexpected error occurred while loading config: {e}. Using default configuration.")
        return default_config

# --- Logging Setup ---
def setup_logging(log_file):
    """
    Sets up the logging system to output messages to a file with timestamps.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout) # Also log to console
        ]
    )
    logging.info(f"Logging initialized. Messages will be saved to '{log_file}'")

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc):
    """
    Callback function when the client connects to the MQTT broker.
    """
    if rc == 0:
        logging.info("Connected to MQTT Broker!")
    else:
        logging.error(f"Failed to connect, return code {rc}")

def on_publish(client, userdata, mid):
    """
    Callback function when a message is published.
    """
    # This callback is useful for tracking message delivery confirmation.
    # For this simple app, we log the message immediately before publishing.
    pass

# --- FTP Folder Management Function ---
def manage_ftp_folder(folder_path):
    """
    Checks the amount of files in the specified folder, calculates average size,
    and then deletes them. This function will be called as the last action of the program.
    """
    logging.info(f"Initiating FTP folder management for: '{folder_path}'")
    
    if not os.path.isdir(folder_path):
        logging.warning(f"Specified FTP folder path does not exist: '{folder_path}'. Cannot manage files.")
        return

    try:
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        num_files = len(files)
        logging.info(f"Found {num_files} files in '{folder_path}'.")

        total_file_size = 0
        if num_files > 0:
            for file_name in files:
                file_path = os.path.join(folder_path, file_name)
                try:
                    total_file_size += os.path.getsize(file_path)
                except OSError as e:
                    logging.warning(f"Could not get size of file '{file_path}': {e}. Skipping this file for size calculation.")
            
            if num_files > 0: # Recalculate num_files based on successfully sized files if needed, or just warn
                average_file_size_bytes = total_file_size / num_files
                logging.info(f"Average file size: {average_file_size_bytes:.2f} bytes ({average_file_size_bytes / 1024:.2f} KB, {average_file_size_bytes / (1024 * 1024):.2f} MB)")
            else:
                logging.info("No files found to calculate average size.")

            logging.info(f"Deleting {num_files} files from '{folder_path}'...")
            for file_name in files:
                file_path = os.path.join(folder_path, file_name)
                try:
                    os.remove(file_path)
                    logging.debug(f"Deleted: {file_path}")
                except OSError as e:
                    logging.error(f"Error deleting file '{file_path}': {e}")
            logging.info("All files deleted from the FTP folder.")
        else:
            logging.info("No files to delete in the FTP folder.")

    except Exception as e:
        logging.critical(f"An error occurred during FTP folder management: {e}", exc_info=True)


# --- Main Application Logic ---
def run_publisher():
    """
    Main function to run the MQTT message publisher.
    """
    config = load_config()
    setup_logging(config["log_file"])

    broker = config["mqtt_broker"]
    port = config["mqtt_port"]
    topic = config["mqtt_topic"]
    # Convert milliseconds to seconds for time.sleep()
    interval_tf_ms = config["interval_true_false"]
    interval_ft_ms = config["interval_false_true"]
    interval_tf_s = interval_tf_ms / 1000.0
    interval_ft_s = interval_ft_ms / 1000.0
    repeats = config["repeats"] # Number of cycles to repeat
    true_message = config["true_message"] # Configurable "true" message
    false_message = config["false_message"] # Configurable "false" message
    ftp_folder_path = config["ftp_folder_to_manage"] # New: FTP folder path from config


    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1) # Specify MQTT protocol version
    client.on_connect = on_connect
    client.on_publish = on_publish

    try:
        logging.info(f"Attempting to connect to MQTT broker: {broker}:{port}")
        client.connect(broker, port, 60)
        client.loop_start() # Start a background thread to handle MQTT network traffic
    except Exception as e:
        logging.error(f"Could not connect to MQTT broker: {e}")
        sys.exit(1) # Exit if connection fails

    logging.info(f"Starting message publication to topic: '{topic}'")
    logging.info(f"Intervals: True -> False = {interval_tf_ms}ms, False -> True = {interval_ft_ms}ms")
    logging.info(f"True message: '{true_message}', False message: '{false_message}'")
    if repeats == -1:
        logging.info("Messages will be sent indefinitely.")
    else:
        logging.info(f"Messages will be sent {repeats} times.")

    try:
        current_repeat = 0
        while repeats == -1 or current_repeat < repeats:
            # Send "true"
            message = true_message
            result = client.publish(topic, message)
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                logging.info(f"Published '{message}' to topic '{topic}' (Cycle {current_repeat + 1}/{'Infinite' if repeats == -1 else repeats})")
            else:
                logging.error(f"Failed to publish '{message}': {mqtt.error_string(result.rc)}")

            time.sleep(interval_tf_s)

            # Send "false"
            message = false_message
            result = client.publish(topic, message)
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                logging.info(f"Published '{message}' to topic '{topic}' (Cycle {current_repeat + 1}/{'Infinite' if repeats == -1 else repeats})")
            else:
                logging.error(f"Failed to publish '{message}': {mqtt.error_string(result.rc)}")

            time.sleep(interval_ft_s)

            if repeats != -1: # Only increment if not infinite
                current_repeat += 1

    except KeyboardInterrupt:
        logging.info("Publisher stopped by user (Ctrl+C).")
    except Exception as e:
        logging.critical(f"An unhandled error occurred: {e}", exc_info=True)
    finally:
        logging.info("Disconnecting from MQTT broker.")
        client.loop_stop() # Stop the background thread
        client.disconnect()
        if repeats != -1: # Only perform file management if repeats is finite (program is ending naturally)
            logging.info(f"Completed {current_repeat} message cycles as configured.")
            logging.info("Waiting 2 seconds before managing FTP folder...")
            time.sleep(2) # Wait for 2 seconds after the last repeat
            manage_ftp_folder(ftp_folder_path) # Call the new function

if __name__ == "__main__":
    run_publisher()
