import pandas as pd
import re
from datetime import datetime, timedelta
import logging
import sys

# --- Configuration for Analysis Script ---
# You can customize these if your log file names are different
MQTT_LOG_FILE = "mqtt_messages.log"
WIRESHARK_FTP_CSV = "wireshark_ftp_log.csv"
OUTPUT_ANALYSIS_FILE = "transfer_analysis_report.txt"

# --- Logging Setup ---
def setup_logging(log_file):
    """
    Sets up logging for the analysis script.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, mode='w'), # Overwrite previous analysis log
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info(f"Analysis logging initialized. Report will be saved to '{log_file}'")

# --- Log Parsing Functions ---
def parse_mqtt_log(log_file):
    """
    Parses the MQTT log file to extract all 'true'/'ON' and 'false'/'OFF' message timestamps.
    Returns a list of dictionaries: [{'timestamp': datetime, 'type': 'true/false'}].
    """
    mqtt_events = []
    # Regex to match log lines containing "Published 'message_content'"
    log_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - INFO - Published '(.+?)' to topic '(.+?)'")

    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = log_pattern.match(line)
                if match:
                    timestamp_str = match.group(1).replace(',', '.') # Convert comma to dot for datetime parsing
                    message_content = match.group(2)
                    try:
                        dt_object = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                        # Determine the type of message based on its content (configurable in original app)
                        if message_content in ["true", "ON"]: # Add other 'true' messages if you configured them
                            mqtt_events.append({'timestamp': dt_object, 'type': 'true'})
                        elif message_content in ["false", "OFF"]: # Add other 'false' messages
                            mqtt_events.append({'timestamp': dt_object, 'type': 'false'})
                    except ValueError as e:
                        logging.warning(f"Could not parse timestamp '{timestamp_str}' from MQTT log: {e}")
    except FileNotFoundError:
        logging.error(f"MQTT log file not found: {log_file}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading MQTT log file {log_file}: {e}")
        sys.exit(1)
    logging.info(f"Found {len(mqtt_events)} total messages in MQTT log.")
    return sorted(mqtt_events, key=lambda x: x['timestamp'])

def parse_wireshark_ftp_log(csv_file):
    """
    Parses the Wireshark FTP CSV log to extract FTP STOR, 226/250, 220/230, QUIT/221 timestamps.
    Returns a list of dictionaries for all relevant FTP events.
    """
    ftp_events = []
    try:
        df = pd.read_csv(csv_file)
        if '_ws.col.Time' not in df.columns or '_ws.col.Info' not in df.columns:
            logging.error(f"Required columns '_ws.col.Time' or '_ws.col.Info' not found in {csv_file}. Please ensure correct export from Wireshark.")
            sys.exit(1)

        for index, row in df.iterrows():
            timestamp_str = str(row['_ws.col.Time'])
            info_str = str(row['_ws.col.Info'])

            try:
                # Parse Wireshark absolute timestamp
                if ' ' in timestamp_str and '.' in timestamp_str:
                    dt_object = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                elif ' ' in timestamp_str:
                    dt_object = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                else:
                    logging.warning(f"Wireshark timestamp '{timestamp_str}' might be relative or unparseable. Ensure 'Time of Day' is selected in Wireshark export settings for absolute timestamps. Skipping row.")
                    continue

                event_type = None
                filename = None # Only for STOR

                if "FTP (Command) STOR" in info_str:
                    event_type = "STOR"
                    filename_match = re.search(r"STOR (.+)", info_str)
                    filename = filename_match.group(1).strip() if filename_match else "unknown_file"
                elif "FTP (Response) 226 Transfer complete" in info_str or "FTP (Response) 250 Requested file action okay, completed" in info_str:
                    event_type = "COMPLETION"
                elif "FTP (Response) 220 Service ready" in info_str or "FTP (Response) 230 User logged in" in info_str:
                    event_type = "CONN_OPEN"
                elif "FTP (Command) QUIT" in info_str or "FTP (Response) 221 Goodbye" in info_str:
                    event_type = "CONN_CLOSE"
                
                if event_type:
                    ftp_events.append({
                        "type": event_type,
                        "timestamp": dt_object,
                        "filename": filename # Will be None for non-STOR events
                    })
            except Exception as e:
                logging.warning(f"Error processing Wireshark CSV row: {row}. Error: {e}")

    except FileNotFoundError:
        logging.error(f"Wireshark FTP CSV file not found: {csv_file}")
        sys.exit(1)
    except pd.errors.EmptyDataError:
        logging.error(f"Wireshark FTP CSV file '{csv_file}' is empty. No data to analyze.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading Wireshark FTP CSV file {csv_file}: {e}")
        sys.exit(1)

    logging.info(f"Found {len([e for e in ftp_events if e['type'] == 'STOR'])} STOR, {len([e for e in ftp_events if e['type'] == 'COMPLETION'])} COMPLETION, {len([e for e in ftp_events if e['type'] == 'CONN_OPEN'])} CONN_OPEN, {len([e for e in ftp_events if e['type'] == 'CONN_CLOSE'])} CONN_CLOSE events in FTP log.")
    return sorted(ftp_events, key=lambda x: x['timestamp'])

# --- Analysis Logic ---
def analyze_transfers(mqtt_events, ftp_events, time_tolerance_seconds_stor=10.0, time_tolerance_seconds_conn=30.0):
    """
    Correlates MQTT 'true' messages with FTP transfers and calculates various durations and overlaps.
    """
    analysis_results = []
    
    # Track previous transfer's completion for overlap detection
    last_transfer_completion_time = None 

    for i, mqtt_event in enumerate(mqtt_events):
        if mqtt_event['type'] == 'true':
            mqtt_true_ts = mqtt_event['timestamp']
            
            found_stor = None
            found_completion = None
            
            # --- 1. Find matching STOR and Completion ---
            # Search for STOR within a tolerance window after mqtt_true_ts
            search_start_time = mqtt_true_ts
            search_end_time = mqtt_true_ts + timedelta(seconds=time_tolerance_seconds_stor)

            # Filter relevant FTP STOR events in the window
            relevant_stors = [
                e for e in ftp_events
                if e['type'] == "STOR" and search_start_time <= e['timestamp'] <= search_end_time
            ]

            if relevant_stors:
                found_stor = relevant_stors[0] # Take the first one found

                # Now find the first completion event *after* this STOR command
                for event in ftp_events:
                    if event['timestamp'] > found_stor['timestamp'] and event['type'] == "COMPLETION":
                        found_completion = event
                        break # Found the first completion after STOR

            if found_stor and found_completion:
                transfer_duration = found_completion['timestamp'] - found_stor['timestamp']
                time_true_to_transfer_start = found_stor['timestamp'] - mqtt_true_ts

                # --- 2. Check for overlap with 'false' message ---
                next_false_mqtt_ts = None
                for j in range(i + 1, len(mqtt_events)):
                    if mqtt_events[j]['type'] == 'false':
                        next_false_mqtt_ts = mqtt_events[j]['timestamp']
                        break

                transfer_completed_after_false_signal = False
                time_overlap_after_false_signal_seconds = None
                if next_false_mqtt_ts and found_completion['timestamp'] > next_false_mqtt_ts:
                    transfer_completed_after_false_signal = True
                    time_overlap_after_false_signal_seconds = (found_completion['timestamp'] - next_false_mqtt_ts).total_seconds()

                # --- 3. Find Connection Open/Close (Heuristic) ---
                conn_opened_time = None
                conn_closed_time = None

                # Find the closest CONN_OPEN before STOR
                for k in reversed(range(len(ftp_events))):
                    if ftp_events[k]['timestamp'] < found_stor['timestamp'] and ftp_events[k]['type'] == "CONN_OPEN":
                        # Check if within a reasonable tolerance (e.g., 30 seconds before STOR)
                        if (found_stor['timestamp'] - ftp_events[k]['timestamp']).total_seconds() <= time_tolerance_seconds_conn:
                            conn_opened_time = ftp_events[k]['timestamp']
                            break
                
                # Find the closest CONN_CLOSE after COMPLETION
                for k in range(len(ftp_events)):
                    if ftp_events[k]['timestamp'] > found_completion['timestamp'] and ftp_events[k]['type'] == "CONN_CLOSE":
                         # Check if within a reasonable tolerance (e.g., 30 seconds after completion)
                        if (ftp_events[k]['timestamp'] - found_completion['timestamp']).total_seconds() <= time_tolerance_seconds_conn:
                            conn_closed_time = ftp_events[k]['timestamp']
                            break

                # --- 4. Check for overlap with previous *transfer* ---
                overlapped_with_previous_transfer = False
                if last_transfer_completion_time and mqtt_true_ts < last_transfer_completion_time:
                    overlapped_with_previous_transfer = True

                analysis_results.append({
                    "mqtt_true_time": mqtt_true_ts,
                    "ftp_stor_time": found_stor['timestamp'],
                    "ftp_completion_time": found_completion['timestamp'],
                    "transfer_duration_seconds": transfer_duration.total_seconds(),
                    "filename": found_stor.get('filename', 'N/A'),
                    "next_false_mqtt_time": next_false_mqtt_ts,
                    "transfer_completed_after_false_signal": transfer_completed_after_false_signal,
                    "time_overlap_after_false_signal_seconds": time_overlap_after_false_signal_seconds,
                    "time_true_to_transfer_start_seconds": time_true_to_transfer_start.total_seconds(),
                    "connection_opened_time": conn_opened_time,
                    "connection_closed_time": conn_closed_time,
                    "overlapped_with_previous_transfer": overlapped_with_previous_transfer,
                })
                
                # Update for next iteration
                last_transfer_completion_time = found_completion['timestamp']
            else:
                logging.info(f"Could not find matching FTP transfer (STOR+COMPLETION) for MQTT 'true' at {mqtt_true_ts}.")

    return analysis_results

# --- Main Execution ---
def run_analysis():
    setup_logging(OUTPUT_ANALYSIS_FILE)

    logging.info("Starting analysis of MQTT and Wireshark logs...")

    mqtt_events = parse_mqtt_log(MQTT_LOG_FILE) # Now gets all MQTT events
    ftp_events = parse_wireshark_ftp_log(WIRESHARK_FTP_CSV)

    if not mqtt_events:
        logging.warning("No messages found in MQTT log. Cannot perform correlation.")
        return
    if not ftp_events:
        logging.warning("No relevant FTP events found in Wireshark log. Cannot perform correlation.")
        return

    # time_tolerance_seconds_stor: Max time (seconds) between MQTT 'true' and FTP STOR.
    # time_tolerance_seconds_conn: Max time (seconds) to look for connection open/close events around transfer.
    analysis_results = analyze_transfers(mqtt_events, ftp_events, 
                                          time_tolerance_seconds_stor=10.0, 
                                          time_tolerance_seconds_conn=30.0)

    if not analysis_results:
        logging.info("No successful FTP transfer correlations found based on provided logs and settings.")
        return

    # --- Generate Report ---
    report_lines = ["--- FTP Transfer Analysis Report ---"]
    report_lines.append(f"Analysis conducted on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"MQTT Log File: {MQTT_LOG_FILE}")
    report_lines.append(f"Wireshark FTP CSV File: {WIRESHARK_FTP_CSV}\n")

    report_lines.append("Individual Transfer Details:\n")
    
    total_transfer_durations = []
    time_true_to_start_durations = []
    overlap_after_false_durations = []
    transfers_after_false_count = 0
    overlapped_with_previous_count = 0

    for i, res in enumerate(analysis_results):
        report_lines.append(f"--- Event {i+1} ---")
        report_lines.append(f"  MQTT 'True' Sent:            {res['mqtt_true_time']}")
        report_lines.append(f"  FTP STOR Command:            {res['ftp_stor_time']} (File: {res['filename']})")
        report_lines.append(f"  Time 'True' to Transfer Start: {res['time_true_to_transfer_start_seconds']:.4f} seconds")
        report_lines.append(f"  FTP Completion:              {res['ftp_completion_time']}")
        report_lines.append(f"  Total Transfer Duration:     {res['transfer_duration_seconds']:.4f} seconds")
        report_lines.append(f"  Next MQTT 'False' Signal:    {res['next_false_mqtt_time'] if res['next_false_mqtt_time'] else 'N/A'}")
        report_lines.append(f"  Completed After 'False' Signal: {'YES' if res['transfer_completed_after_false_signal'] else 'NO'}")
        if res['transfer_completed_after_false_signal']:
            report_lines.append(f"  Time Still Transferring After 'False': {res['time_overlap_after_false_signal_seconds']:.4f} seconds")
            transfers_after_false_count += 1
            overlap_after_false_durations.append(res['time_overlap_after_false_signal_seconds'])
        else:
            report_lines.append(f"  Time Still Transferring After 'False': N/A")

        report_lines.append(f"  FTP Connection Opened:       {res['connection_opened_time'] if res['connection_opened_time'] else 'N/A'}")
        report_lines.append(f"  FTP Connection Closed:       {res['connection_closed_time'] if res['connection_closed_time'] else 'N/A'}")
        report_lines.append(f"  Overlapped with Previous Transfer: {'YES' if res['overlapped_with_previous_transfer'] else 'NO'}\n")
        
        total_transfer_durations.append(res['transfer_duration_seconds'])
        time_true_to_start_durations.append(res['time_true_to_transfer_start_seconds'])
        if res['overlapped_with_previous_transfer']:
            overlapped_with_previous_count += 1

    report_lines.append("--- Summary Statistics ---")
    if total_transfer_durations:
        report_lines.append(f"Total Correlated Transfers: {len(analysis_results)}")
        report_lines.append(f"\nAverage Time 'True' to Transfer Start: {sum(time_true_to_start_durations) / len(time_true_to_start_durations):.4f} seconds")
        report_lines.append(f"Min Time 'True' to Transfer Start:     {min(time_true_to_start_durations):.4f} seconds")
        report_lines.append(f"Max Time 'True' to Transfer Start:     {max(time_true_to_start_durations):.4f} seconds")

        report_lines.append(f"\nAverage Total Transfer Duration: {sum(total_transfer_durations) / len(total_transfer_durations):.4f} seconds")
        report_lines.append(f"Min Total Transfer Duration:     {min(total_transfer_durations):.4f} seconds")
        report_lines.append(f"Max Total Transfer Duration:     {max(total_transfer_durations):.4f} seconds")
        
        report_lines.append(f"\nTransfers Completed AFTER 'False' Signal: {transfers_after_false_count} out of {len(analysis_results)} ({ (transfers_after_false_count / len(analysis_results) * 100):.2f }%)")
        if overlap_after_false_durations:
            report_lines.append(f"  Average Overlap After 'False': {sum(overlap_after_false_durations) / len(overlap_after_false_durations):.4f} seconds")
            report_lines.append(f"  Max Overlap After 'False':     {max(overlap_after_false_durations):.4f} seconds")
        
        report_lines.append(f"\nNew 'True' Messages Sent While Previous Transfer was Active: {overlapped_with_previous_count} out of {len(analysis_results)} ({ (overlapped_with_previous_count / len(analysis_results) * 100):.2f }%)")
    else:
        report_lines.append("No transfer durations to summarize.")

    # Save report to file
    with open(OUTPUT_ANALYSIS_FILE, 'w') as f:
        f.write("\n".join(report_lines))
    logging.info(f"Analysis complete. Report saved to '{OUTPUT_ANALYSIS_FILE}'")

if __name__ == "__main__":
    run_analysis()
