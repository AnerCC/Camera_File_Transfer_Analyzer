import json
import time
import logging
import paho.mqtt.client as mqtt
import sys
import os
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import subprocess
import platform
import pandas as pd

# --- Configuration Loading ---
def load_config(config_file="config.json"):
    """
    Loads configuration from a JSON file, providing default values for missing keys.
    """
    default_config = {
        "mqtt_broker": "broker.emqx.io",
        "mqtt_port": 1883,
        "mqtt_topic": "home/status/power",
        "interval_true_false": 5000,
        "interval_false_true": 10000,
        "log_file": "mqtt_activity.log",
        "repeats": 1,
        "true_message": "true",
        "false_message": "false",
        "ftp_folder_to_manage": "./ftp_images",
        "ftp_management_delay_seconds": 2,
        "google_sheet_name": "My_Test_Results",
        "google_worksheet_name": "Test_Data",
        "tshark_enabled": False,
        "tshark_interface": "",
        "tshark_temp_capture_file": "temp_capture.pcap",
        "camera_ips": []
    }
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
            return {**default_config, **config}
    except FileNotFoundError:
        logging.error(f"Config file '{config_file}' not found. Using defaults.")
        return default_config
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from '{config_file}'. Using defaults.")
        return default_config
    except Exception as e:
        logging.critical(f"Unexpected error loading config: {e}. Using defaults.")
        return default_config

# --- Logging Setup ---
def setup_logging(log_file):
    """Sets up logging to both a file and the console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, mode='a'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info(f"Logging initialized. Output will be saved to '{log_file}'")

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc):
    """Callback for MQTT connection."""
    if rc == 0:
        logging.info("Successfully connected to MQTT Broker!")
    else:
        logging.error(f"Failed to connect to MQTT, return code {rc}. Exiting.")
        sys.exit(1)

def on_publish(client, userdata, mid):
    """Callback for MQTT message publication (not actively used)."""
    pass

# --- FTP Folder Management ---
def manage_specific_ftp_folder(folder_path):
    """Checks file count, calculates average size, and deletes files in a folder."""
    logging.info(f"Managing FTP folder: '{folder_path}'")
    if not os.path.isdir(folder_path):
        logging.warning(f"FTP folder not found: '{folder_path}'.")
        return 0, 0.0, 0

    try:
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        num_before = len(files)
        total_size = sum(os.path.getsize(os.path.join(folder_path, f)) for f in files)
        avg_size_bytes = total_size / num_before if num_before > 0 else 0.0
        
        logging.info(f"Found {num_before} files with avg size {avg_size_bytes / (1024*1024):.4f} MB.")

        for f in files:
            os.remove(os.path.join(folder_path, f))
        
        time.sleep(1) # Wait for filesystem to update
        num_after = len([f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))])
        logging.info(f"Deleted {num_before - num_after} files. {num_after} files remain.")
        
        return num_before, avg_size_bytes, num_after
    except Exception as e:
        logging.error(f"Error managing folder '{folder_path}': {e}")
        return 0, 0.0, 0

# --- Google Sheets Integration ---
def init_google_sheet(sheet_name, worksheet_name, credentials_file="google_credentials.json"):
    """Initializes connection to Google Sheets and returns the worksheet."""
    try:
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), credentials_file)
        creds = ServiceAccountCredentials.from_json_keyfile_name(creds_path, scope)
        client = gspread.authorize(creds)
        sheet = client.open(sheet_name)

        try:
            worksheet = sheet.worksheet(worksheet_name)
        except gspread.exceptions.WorksheetNotFound:
            headers = [
                "Timestamp", "Camera_IP", "interval_true_false_ms", "interval_false_true_ms",
                "repeats_configured", "files_before_delete", "files_after_delete",
                "avg_image_size_MB", "total_retransmissions", "zero_window_count",
                "window_full_count", "avg_rtt_ms", "lost_segments_count",
                "duplicate_ack_count", "measured_throughput_Mbps", "num_cameras_detected",
                "ftp_conn_opened_timestamp", "ftp_conn_closed_timestamp", "FPS_Manual"
            ]
            worksheet = sheet.add_worksheet(title=worksheet_name, rows=100, cols=len(headers))
            worksheet.append_row(headers)
            logging.info(f"Created new worksheet '{worksheet_name}' with headers.")
        
        return worksheet
    except FileNotFoundError:
        logging.critical(f"Google credentials file not found at '{creds_path}'.")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Failed to connect to Google Sheets API: {e}", exc_info=True)
        sys.exit(1)

# --- Tshark Helper Functions ---
def get_rtt_field_name():
    """Detects the correct RTT field name for the installed tshark version."""
    try:
        result = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, check=True, timeout=10)
        if "tcp.analysis.ack_rtt" in result.stdout:
            return "tcp.analysis.ack_rtt"
        if "tcp.analysis.rtt" in result.stdout:
            return "tcp.analysis.rtt"
        logging.warning("No RTT field found in tshark. RTT metrics will be unavailable.")
        return None
    except Exception as e:
        logging.warning(f"Could not detect tshark RTT field: {e}. RTT metrics will be unavailable.")
        return None

def calculate_metrics(df, duration_s, rtt_field, camera_ips):
    """
    Calculates network metrics from a pandas DataFrame.
    This is the corrected version that handles missing columns properly.
    """
    metrics = {}

    # FIXED: Use the safer `if col in df.columns` check to prevent incorrect zero values.
    metrics["total_retransmissions"] = int(df['tcp.analysis.retransmission'].sum()) if 'tcp.analysis.retransmission' in df.columns else 0
    metrics["zero_window_count"]     = int(df['tcp.analysis.zero_window'].sum()) if 'tcp.analysis.zero_window' in df.columns else 0
    metrics["window_full_count"]     = int(df['tcp.analysis.window_full'].sum()) if 'tcp.analysis.window_full' in df.columns else 0
    metrics["lost_segments_count"]   = int(df['tcp.analysis.lost_segment'].sum()) if 'tcp.analysis.lost_segment' in df.columns else 0
    metrics["duplicate_ack_count"]   = int(df['tcp.analysis.duplicate_ack'].sum()) if 'tcp.analysis.duplicate_ack' in df.columns else 0

    # FIXED: Reverted to 1024*1024 for throughput calculation to match original logic.
    if duration_s > 0 and 'frame.len' in df.columns:
        total_bytes = df['frame.len'].sum()
        metrics["measured_throughput_Mbps"] = (total_bytes * 8) / (duration_s * 1024 * 1024)
    else:
        metrics["measured_throughput_Mbps"] = 0.0

    # RTT is provided in seconds by tshark, so multiply by 1000 to get milliseconds.
    if rtt_field in df.columns and not df[rtt_field].dropna().empty:
        metrics["avg_rtt_ms"] = df[rtt_field].dropna().mean() * 1000
    else:
        metrics["avg_rtt_ms"] = 0.0

    # --- Timestamps ---
    opened_ts, closed_ts = pd.NaT, pd.NaT
    if 'tcp.flags.syn' in df.columns and 'ip.src' in df.columns:
        syn_events = df[(df['tcp.flags.syn'] == 1) & (df['ip.src'].isin(camera_ips))]
        if not syn_events.empty:
            opened_ts = syn_events['frame.time'].min()

    if 'tcp.flags.fin' in df.columns and 'ip.src' in df.columns and 'ip.dst' in df.columns:
        fin_rst_events = df[((df['tcp.flags.fin'] == 1) | (df['tcp.flags.reset'] == 1)) & ((df['ip.src'].isin(camera_ips)) | (df['ip.dst'].isin(camera_ips)))]
        if not fin_rst_events.empty:
            closed_ts = fin_rst_events['frame.time'].max()

    # Fallback to FTP commands if primary TCP flags aren't found
    if pd.isna(opened_ts) and 'ftp.response.code' in df.columns:
        ftp_open_events = df[df['ftp.response.code'].str.startswith(('220', '230')) | df.get('ftp.request.command', pd.Series(dtype=str)).str.upper().str.contains('USER')]
        if not ftp_open_events.empty:
            opened_ts = ftp_open_events['frame.time'].min()

    if pd.isna(closed_ts) and 'ftp.request.command' in df.columns:
        ftp_close_events = df[df['ftp.request.command'].str.upper().str.contains('QUIT') | df.get('ftp.response.code', pd.Series(dtype=str)).str.startswith('221')]
        if not ftp_close_events.empty:
            closed_ts = ftp_close_events['frame.time'].max()

    metrics["ftp_conn_opened_timestamp"] = opened_ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if pd.notna(opened_ts) else ""
    metrics["ftp_conn_closed_timestamp"] = closed_ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if pd.notna(closed_ts) else ""

    return metrics

# --- Tshark Analysis Function ---
def analyze_tshark_capture(capture_file_path, capture_duration_s, configured_camera_ips):
    """Exports and analyzes tshark capture data for network metrics."""
    default_metrics = {
        "total_retransmissions": 0, "zero_window_count": 0, "window_full_count": 0,
        "avg_rtt_ms": 0.0, "lost_segments_count": 0, "duplicate_ack_count": 0,
        "measured_throughput_Mbps": 0.0, "num_cameras_detected": 0,
        "ftp_conn_opened_timestamp": "", "ftp_conn_closed_timestamp": ""
    }

    tshark_fields = [
        "-e", "frame.time_epoch", "-e", "frame.len", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.analysis.retransmission", "-e", "tcp.analysis.zero_window",
        "-e", "tcp.analysis.window_full", "-e", "tcp.analysis.lost_segment",
        "-e", "tcp.analysis.duplicate_ack", "-e", "ftp.request.command",
        "-e", "ftp.response.code", "-e", "tcp.flags.syn", "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset"
    ]
    rtt_field = get_rtt_field_name()
    if rtt_field:
        tshark_fields.extend(["-e", rtt_field])

    temp_csv_file = "temp_tshark_analysis.csv"
    tshark_command = ["tshark", "-r", capture_file_path, "-T", "fields"] + tshark_fields + ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]
    
    try:
        logging.info("Exporting tshark data to CSV...")
        result = subprocess.run(tshark_command, check=True, capture_output=True, text=True)
        with open(temp_csv_file, 'w', newline='', encoding='utf-8') as f:
            f.write(result.stdout)
    except Exception as e:
        logging.error(f"Tshark export failed: {e}", exc_info=True)
        return {"overall": default_metrics, "per_camera": []}

    try:
        df = pd.read_csv(temp_csv_file)
        if 'frame.time_epoch' in df.columns:
            df.rename(columns={'frame.time_epoch': 'frame.time'}, inplace=True)
            df['frame.time'] = pd.to_datetime(df['frame.time'], unit='s', errors='coerce')
        else: # Fallback
            df['frame.time'] = pd.to_datetime(df['frame.time'], errors='coerce')

        # Clean up data types
        for col in df.columns:
            if col.startswith(('tcp.analysis', 'tcp.flags', 'frame.len')):
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            elif col.startswith(('ip.', 'ftp.')):
                df[col] = df[col].astype(str).str.strip().fillna('')

        # --- Overall Analysis ---
        detected_ips = {ip for ip in configured_camera_ips if (df['ip.src'] == ip).any() or (df['ip.dst'] == ip).any()}
        overall_metrics = calculate_metrics(df, capture_duration_s, rtt_field, configured_camera_ips)
        overall_metrics["num_cameras_detected"] = len(detected_ips)
        logging.info(f"Overall analysis results: {overall_metrics}")

        # --- Per-Camera Analysis ---
        per_camera_metrics_list = []
        for ip in detected_ips:
            df_cam = df[(df['ip.src'] == ip) | (df['ip.dst'] == ip)].copy()
            cam_metrics = calculate_metrics(df_cam, capture_duration_s, rtt_field, [ip])
            cam_metrics["num_cameras_detected"] = 1
            per_camera_metrics_list.append({"ip": ip, "metrics": cam_metrics})
            logging.info(f"Analysis for {ip}: {cam_metrics}")

    except Exception as e:
        logging.error(f"Error analyzing tshark CSV: {e}", exc_info=True)
        return {"overall": default_metrics, "per_camera": []}
    finally:
        if os.path.exists(temp_csv_file):
            os.remove(temp_csv_file)
    
    return {"overall": overall_metrics, "per_camera": per_camera_metrics_list}

# --- Main Application Logic ---
def run_analyzer():
    """Main function to run the MQTT publisher and analysis."""
    config = load_config()
    setup_logging(config["log_file"])

    worksheet = init_google_sheet(config["google_sheet_name"], config["google_worksheet_name"])

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    client.on_connect = on_connect
    client.on_publish = on_publish
    try:
        client.connect(config["mqtt_broker"], config["mqtt_port"], 60)
        client.loop_start()
    except Exception as e:
        logging.critical(f"Could not connect to MQTT broker: {e}. Exiting.", exc_info=True)
        sys.exit(1)

    tshark_process = None
    capture_duration_s = 0
    if config["tshark_enabled"]:
        if not config["tshark_interface"]:
            logging.error("Tshark is enabled but 'tshark_interface' is not set in config.json.")
        else:
            repeats = config["repeats"]
            duration = (repeats * (config["interval_true_false"] + config["interval_false_true"])) / 1000 if repeats != -1 else 600
            capture_duration_s = max(duration, 5)

            capture_filter = " or ".join([f"host {ip}" for ip in config["camera_ips"]])
            tshark_cmd = [
                "tshark", "-i", config["tshark_interface"], "-w", config["tshark_temp_capture_file"],
                "-a", f"duration:{capture_duration_s}"
            ]
            if capture_filter:
                tshark_cmd.extend(["-f", capture_filter])
                logging.info(f"Starting tshark on '{config['tshark_interface']}' for {capture_duration_s:.2f}s with filter: '{capture_filter}'")
            else:
                 logging.info(f"Starting tshark on '{config['tshark_interface']}' for {capture_duration_s:.2f}s without filter.")

            try:
                is_windows = platform.system() == "Windows"
                p_kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if is_windows else {"preexec_fn": os.setsid}
                tshark_process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **p_kwargs)
                time.sleep(1)
            except Exception as e:
                logging.error(f"Failed to start tshark: {e}", exc_info=True)
                tshark_process = None
    
    try:
        logging.info(f"Starting MQTT publication to topic '{config['mqtt_topic']}' for {config['repeats']} cycles.")
        loop_iterator = range(config['repeats']) if config['repeats'] != -1 else iter(int, 1)
        for i in loop_iterator:
            client.publish(config["mqtt_topic"], config["true_message"])
            logging.info(f"Published '{config['true_message']}' (Cycle {i+1})")
            time.sleep(config["interval_true_false"] / 1000.0)

            client.publish(config["mqtt_topic"], config["false_message"])
            logging.info(f"Published '{config['false_message']}' (Cycle {i+1})")
            time.sleep(config["interval_false_true"] / 1000.0)
        logging.info("Finished all test cycles.")
    except KeyboardInterrupt:
        logging.info("Test interrupted by user.")
    except Exception as e:
        logging.critical(f"Unhandled error during MQTT publishing: {e}", exc_info=True)
    finally:
        client.loop_stop()
        client.disconnect()
        logging.info("Disconnected from MQTT broker.")

        if tshark_process and tshark_process.poll() is None:
            logging.info("Stopping tshark capture...")
            if platform.system() == "Windows":
                tshark_process.terminate()
            else:
                os.killpg(os.getpgid(tshark_process.pid), subprocess.signal.SIGTERM)
            tshark_process.communicate(timeout=10)
            
        logging.info(f"Waiting {config['ftp_management_delay_seconds']}s before final analysis.")
        time.sleep(config['ftp_management_delay_seconds'])

        per_camera_ftp_data = {}
        for ip in config["camera_ips"]:
            sub_folder = os.path.join(config["ftp_folder_to_manage"], ip.split('.')[-1])
            num_before, avg_bytes, num_after = manage_specific_ftp_folder(sub_folder)
            per_camera_ftp_data[ip] = {"files_before": num_before, "avg_bytes_per_file": avg_bytes, "files_after": num_after}

        analysis_results = None
        if config["tshark_enabled"] and os.path.exists(config["tshark_temp_capture_file"]):
            analysis_results = analyze_tshark_capture(config["tshark_temp_capture_file"], capture_duration_s, config["camera_ips"])
        
        current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        rows_to_append = []

        if analysis_results:
            total_files_before = sum(d['files_before'] for d in per_camera_ftp_data.values())
            total_files_after = sum(d['files_after'] for d in per_camera_ftp_data.values())
            total_bytes = sum(d['avg_bytes_per_file'] * d['files_before'] for d in per_camera_ftp_data.values())
            avg_size_mb = (total_bytes / total_files_before) / (1024*1024) if total_files_before > 0 else 0
            
            o_metrics = analysis_results["overall"]
            overall_row = [
                current_timestamp, "Overall", config["interval_true_false"], config["interval_false_true"],
                config["repeats"], total_files_before, total_files_after, f"{avg_size_mb:.4f}",
                o_metrics["total_retransmissions"], o_metrics["zero_window_count"], o_metrics["window_full_count"],
                f"{o_metrics['avg_rtt_ms']:.2f}", o_metrics["lost_segments_count"], o_metrics["duplicate_ack_count"],
                f"{o_metrics['measured_throughput_Mbps']:.4f}", o_metrics["num_cameras_detected"],
                o_metrics["ftp_conn_opened_timestamp"], o_metrics["ftp_conn_closed_timestamp"], ""
            ]
            rows_to_append.append(overall_row)
            
            for cam_data in analysis_results["per_camera"]:
                ip = cam_data["ip"]
                c_metrics = cam_data["metrics"]
                ftp_data = per_camera_ftp_data.get(ip, {})
                avg_size_mb = ftp_data.get("avg_bytes_per_file", 0) / (1024*1024)
                
                cam_row = [
                    current_timestamp, ip, config["interval_true_false"], config["interval_false_true"],
                    config["repeats"], ftp_data.get("files_before", 0), ftp_data.get("files_after", 0), f"{avg_size_mb:.4f}",
                    c_metrics["total_retransmissions"], c_metrics["zero_window_count"], c_metrics["window_full_count"],
                    f"{c_metrics['avg_rtt_ms']:.2f}", c_metrics["lost_segments_count"], c_metrics["duplicate_ack_count"],
                    f"{c_metrics['measured_throughput_Mbps']:.4f}", c_metrics["num_cameras_detected"],
                    c_metrics["ftp_conn_opened_timestamp"], c_metrics["ftp_conn_closed_timestamp"], ""
                ]
                rows_to_append.append(cam_row)
        try:
            if rows_to_append:
                worksheet.append_rows(rows_to_append)
                logging.info(f"Successfully appended {len(rows_to_append)} rows to Google Sheet.")
        except Exception as e:
            logging.error(f"Failed to append data to Google Sheet: {e}", exc_info=True)

        if os.path.exists(config["tshark_temp_capture_file"]):
            os.remove(config["tshark_temp_capture_file"])
        
        logging.info("Analyzer tool finished operations.")

if __name__ == "__main__":
    run_analyzer()
