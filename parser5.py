import streamlit as st
import pandas as pd
import struct
import re
from typing import Dict, List, Any, Optional, Tuple

class JT1078Parser:
    def __init__(self):
        # Parameter ID to name mapping based on Table 32
        self.parameter_names = {
            0x0011: "APN username",
            0x0012: "APN password",
            0x0013: "Main server IP/domain",
            0x0017: "Backup server IP/domain",
            0x0018: "Main server port",
            0xF000: "Device ID",
            0xF004: "NTP server address",
            0xF005: "NTP server port",
            0xF006: "Time zone",
            0xF007: "Protocol type",
            0xF009: "Protocol encryption",
            0xF00A: "Position Galaxy",
            0xF00B: "WiFi enable",
            0xF00C: "WiFi work mode",
            0xF00D: "Max AP of WiFi",
            0xF00E: "WiFi scan time",
            0xF00F: "BT enable",
            0xF010: "BT work mode",
            0xF011: "Max BT nodes",
            0xF012: "BT scan timeout",
            0xF013: "BT single scan time",
            0xF014: "BT sensor report mask",
            0xF017: "Communication protocol",
            0xF018: "Report mask",
            0xF019: "Accelerometer enable",
            0xF01A: "Accelerometer sensitivity",
            0xF01B: "Accelerometer range",
            0xF01C: "Accelerometer motion times",
            0xF01D: "Accelerometer motion duration",
            0xF01E: "Accelerometer trigger interval",
            0xF01F: "Accelerometer report mask",
            0xF020: "Light sensor enable",
            0xF021: "Light sensor threshold",
            0xF022: "Light trigger interval",
            0xF023: "Temp/humidity enable",
            0xF024: "Upper temp limit",
            0xF025: "Lower temp limit",
            0xF026: "Upper humidity limit",
            0xF027: "Lower humidity limit",
            0xF028: "Temp/humidity trigger interval",
            0xF029: "GNSS enable",
            0xF02A: "Device working mode",
            0xF02B: "Backup server port",
            0xF02C: "Buffer enable",
            0xF02D: "Server ack enable",
            0xF02E: "Reporting interval",
            0xF02F: "Sampling interval",
            0xF030: "AT command transparent"
        }
        
        # Define all possible columns for filtering
        self.all_columns = [
            "Message Type", "Device ID", "Sequence Number", "Data Type", "GNSS Fixed", 
            "Latitude", "Longitude", "Time",
            "CSQ", "GPS Satellites", "Base Station", "WiFi APs", "Firmware",
            "Light", "Temperature", "Humidity", "Battery Voltage", "Battery Percentage",
            "Battery Status", "Sampling Interval", "Reporting Interval", "Network Mode"
        ]
        
    def parse_messages(self, messages_text: str) -> List[Dict[str, Any]]:
        """Parse multiple messages from text containing hex strings"""
        parsed_messages = []
        
        lines = messages_text.strip().split('\n')
        for line in lines:
            line = line.strip()
            
            # Extract hex message using regex - more robust pattern
            hex_matches = re.findall(r'(7e[0-9a-fA-F]{20,}7e)', line)
            
            if hex_matches:
                hex_message = hex_matches[0]
                if len(hex_message) >= 40:  # Minimum reasonable length
                    try:
                        parsed_msg = self.parse_single_message(hex_message)
                        if parsed_msg:
                            parsed_messages.append(parsed_msg)
                    except Exception as e:
                        continue
        
        return parsed_messages
    
    def parse_single_message(self, hex_message: str) -> Optional[Dict[str, Any]]:
        """Parse a single hex message"""
        try:
            # Clean the message - ensure proper hex format
            hex_message = ''.join([c for c in hex_message if c in '0123456789abcdefABCDEF'])
            
            # Validate message length and structure
            if len(hex_message) < 40 or not hex_message.startswith('7e') or not hex_message.endswith('7e'):
                return None
            
            message_bytes = bytes.fromhex(hex_message)
            
            # Validate message structure
            if (message_bytes[0] != 0x7e or message_bytes[-1] != 0x7e or 
                len(message_bytes) < 20):
                return None
            
            # Get message body length from properties (bytes 3-4)
            body_properties = int.from_bytes(message_bytes[3:5], byteorder='big')
            body_length = body_properties & 0x03FF  # Lower 10 bits
            
            # Validate total message length
            total_expected_length = 1 + 2 + 2 + 6 + 2 + body_length + 1 + 1  # flag + header + props + devid + seq + body + checksum + flag
            if len(message_bytes) != total_expected_length:
                return None
            
            message_id = int.from_bytes(message_bytes[1:3], byteorder='big')
            
            if message_id == 0x0200:
                return self.parse_0200_message(message_bytes)
            elif message_id == 0x0104:
                return self.parse_0104_message(message_bytes)
            elif message_id == 0x8103:
                return self.parse_8103_message(message_bytes)
            return None
                
        except Exception as e:
            return None
    
    def parse_0200_message(self, message_bytes: bytes) -> Dict[str, Any]:
        """Parse 0x0200 Device Basic Information message - FIXED VERSION"""
        result = {}
        
        # Get message body length
        body_properties = int.from_bytes(message_bytes[3:5], byteorder='big')
        body_length = body_properties & 0x03FF
        
        # Device ID (bytes 5-10) - BCD encoded
        device_id_bytes = message_bytes[5:11]
        result['device_id'] = ''.join([f'{b:02x}' for b in device_id_bytes])
        
        # Message sequence number (bytes 11-12)
        result['sequence_number'] = message_bytes[11:13].hex()
        
        # Alarm sign (bytes 13-16)
        alarm_sign = int.from_bytes(message_bytes[13:17], byteorder='big')
        result['alarm_sign'] = {
            'motion_alarm': bool(alarm_sign & (1 << 15)),
            'raw_value': alarm_sign
        }
        
        # Status (bytes 17-20) - Detailed parsing
        status = int.from_bytes(message_bytes[17:21], byteorder='big')
        
        # Parse all status bits according to documentation
        result['status'] = {
            'buffered_data': bool(status & (1 << 31)),  # Bit 31: 0-real time data 1-buffer data
            'reserved_30': bool(status & (1 << 30)),    # Bit 30: Reserved
            
            # Bits 27-29: network modes
            'network_mode': (status >> 27) & 0x07,      # 000-UNREGISTERED; 001-GSM; 010-LTE; 011-CATM; 100-NBIOT
            
            # Bits 5-26: Reserved
            'sampled_data': bool(status & (1 << 4)),    # Bit 4: 0-Unsampled data;1-Sampled data
            'west_longitude': bool(status & (1 << 3)),  # Bit 3: 0-east longitude 1-west longitude
            'south_latitude': bool(status & (1 << 2)),  # Bit 2: 0-north latitude 1-south latitude
            'gnss_fixed': bool(status & (1 << 1)),      # Bit 1: 0-GNSS position unfix  1-GNSS position fix
            'reserved_0': bool(status & 1),             # Bit 0: Reserved
            
            'raw_value': status
        }
        
        # Map network mode to human-readable string
        network_modes = {
            0: "UNREGISTERED",
            1: "GSM",
            2: "LTE",
            3: "CATM",
            4: "NBIOT"
        }
        result['status']['network_mode_str'] = network_modes.get(result['status']['network_mode'], "UNKNOWN")
        
        # Latitude (bytes 21-24) - *10^6, accurate to 0.000001 degree
        latitude_raw = int.from_bytes(message_bytes[21:25], byteorder='big', signed=False)
        latitude = latitude_raw / 1000000.0
        if result['status']['south_latitude']:
            latitude = -latitude
        result['latitude'] = latitude
        
        # Longitude (bytes 25-28) - *10^6, accurate to 0.000001 degree
        longitude_raw = int.from_bytes(message_bytes[25:29], byteorder='big', signed=False)
        longitude = longitude_raw / 1000000.0
        if result['status']['west_longitude']:
            longitude = -longitude
        result['longitude'] = longitude
        
        # Altitude (bytes 29-30) - meters
        result['altitude'] = int.from_bytes(message_bytes[29:31], byteorder='big')
        
        # Speed (bytes 31-32) - 1/10 km/h
        result['speed'] = int.from_bytes(message_bytes[31:33], byteorder='big') / 10.0
        
        # Direction (bytes 33-34) - 0-359 degrees
        result['direction'] = int.from_bytes(message_bytes[33:35], byteorder='big')
        
        # Time (bytes 35-40) - BCD encoded: YY-MM-DD-hh-mm-ss
        time_bytes = message_bytes[35:41]
        result['time'] = self.parse_bcd_time(time_bytes)
        
        # Extension information starts at byte 41 and goes until checksum
        extension_start = 41
        extension_end = len(message_bytes) - 2  # Before checksum and final flag
        
        if extension_end > extension_start:
            extension_data = message_bytes[extension_start:extension_end]
            result['extension_info'] = self.parse_extension_info(extension_data)
        else:
            result['extension_info'] = {}
        
        result['message_type'] = '0x0200 - Device Basic Information'
        return result
    
    def parse_0104_message(self, message_bytes: bytes) -> Dict[str, Any]:
        """Parse 0x0104 Device Query Response message"""
        result = {}
        
        # Get message body length
        body_properties = int.from_bytes(message_bytes[3:5], byteorder='big')
        body_length = body_properties & 0x03FF
        
        # Device ID (bytes 5-10) - BCD encoded
        device_id_bytes = message_bytes[5:11]
        result['device_id'] = ''.join([f'{b:02x}' for b in device_id_bytes])
        
        # Message sequence number (bytes 11-12)
        result['sequence_number'] = message_bytes[11:13].hex()
        
        # Response sequence number (bytes 13-14)
        result['response_sequence'] = message_bytes[13:15].hex()
        
        # Total number of response parameters (byte 15)
        total_params = message_bytes[15]
        result['total_parameters'] = total_params
        
        # Parse parameters (starting from byte 16)
        parameters = []
        pos = 16
        
        for i in range(total_params):
            if pos + 5 > len(message_bytes) - 2:  # -2 for checksum and flag
                break
                
            # Parameter ID (4 bytes)
            param_id = int.from_bytes(message_bytes[pos:pos+4], byteorder='big')
            pos += 4
            
            # Parameter length (1 byte)
            param_length = message_bytes[pos]
            pos += 1
            
            # Parameter value
            if pos + param_length > len(message_bytes) - 2:
                break
                
            param_value = message_bytes[pos:pos+param_length]
            pos += param_length
            
            # Decode parameter value based on type
            decoded_value = self.decode_parameter_value(param_id, param_value)
            
            parameters.append({
                'id': f'0x{param_id:04X}',
                'name': self.parameter_names.get(param_id, 'Unknown'),
                'length': param_length,
                'value': decoded_value,
                'raw_value': param_value.hex()
            })
        
        result['parameters'] = parameters
        result['message_type'] = '0x0104 - Device Query Response(ACK)'
        return result
    
    def parse_8103_message(self, message_bytes: bytes) -> Dict[str, Any]:
        """Parse 0x8103 Configuration Commands Parameters message"""
        result = {}
        
        # Get message body length
        body_properties = int.from_bytes(message_bytes[3:5], byteorder='big')
        body_length = body_properties & 0x03FF
        
        # Device ID (bytes 5-10) - BCD encoded
        device_id_bytes = message_bytes[5:11]
        result['device_id'] = ''.join([f'{b:02x}' for b in device_id_bytes])
        
        # Message sequence number (bytes 11-12)
        result['sequence_number'] = message_bytes[11:13].hex()
        
        # Total number of parameters (byte 13)
        total_params = message_bytes[13]
        result['total_parameters'] = total_params
        
        # Parse parameters (starting from byte 14)
        parameters = []
        pos = 14
        
        for i in range(total_params):
            if pos + 5 > len(message_bytes) - 2:  # -2 for checksum and flag
                break
                
            # Parameter ID (4 bytes)
            param_id = int.from_bytes(message_bytes[pos:pos+4], byteorder='big')
            pos += 4
            
            # Parameter length (1 byte)
            param_length = message_bytes[pos]
            pos += 1
            
            # Parameter value
            if pos + param_length > len(message_bytes) - 2:
                break
                
            param_value = message_bytes[pos:pos+param_length]
            pos += param_length
            
            # Decode parameter value based on type
            decoded_value = self.decode_parameter_value(param_id, param_value)
            
            parameters.append({
                'id': f'0x{param_id:04X}',
                'name': self.parameter_names.get(param_id, 'Unknown'),
                'length': param_length,
                'value': decoded_value,
                'raw_value': param_value.hex()
            })
        
        result['parameters'] = parameters
        result['message_type'] = '0x8103 - Configuration Commands Parameters'
        return result
    
    def decode_parameter_value(self, param_id: int, param_value: bytes) -> Any:
        """Decode parameter value based on parameter ID and data type"""
        try:
            # Handle string parameters
            if param_id in [0x0011, 0x0012, 0x0013, 0x0017, 0xF000, 0xF004, 0xF030]:
                # Remove null bytes and decode as ASCII
                clean_data = bytes([b for b in param_value if b != 0])
                return clean_data.decode('ascii', errors='ignore').strip()
            
            # Handle DWORD parameters (4 bytes)
            elif param_id in [0x0018, 0xF005, 0xF01D, 0xF01E, 0xF022, 0xF028, 
                            0xF02B, 0xF02E, 0xF02F]:
                if len(param_value) >= 4:
                    return int.from_bytes(param_value[:4], byteorder='big')
            
            # Handle WORD parameters (2 bytes)
            elif param_id in [0xF00E, 0xF013, 0xF01C, 0xF021, 0xF024, 0xF025, 
                            0xF026, 0xF027]:
                if len(param_value) >= 2:
                    return int.from_bytes(param_value[:2], byteorder='big')
            
            # Handle BYTE parameters (1 byte)
            elif param_id in [0xF006, 0xF007, 0xF009, 0xF00A, 0xF00B, 0xF00C, 
                            0xF00D, 0xF00F, 0xF010, 0xF011, 0xF012, 0xF014, 
                            0xF017, 0xF019, 0xF01A, 0xF01B, 0xF01F, 0xF020, 
                            0xF023, 0xF029, 0xF02A, 0xF02C, 0xF02D]:
                if len(param_value) >= 1:
                    return param_value[0]
            
            # Handle F018 (Report mask) as DWORD
            elif param_id == 0xF018 and len(param_value) >= 4:
                return int.from_bytes(param_value[:4], byteorder='big')
            
            # Default: return as hex string
            return param_value.hex()
            
        except Exception:
            return param_value.hex()
    
    def parse_bcd_time(self, time_bytes: bytes) -> str:
        """Parse BCD encoded time correctly"""
        try:
            if len(time_bytes) != 6:
                return "Invalid time"
            
            # Convert each byte to two BCD digits
            digits = []
            for byte in time_bytes:
                digit1 = (byte >> 4) & 0x0F
                digit2 = byte & 0x0F
                digits.append(str(digit1))
                digits.append(str(digit2))
            
            if len(digits) != 12:
                return "Invalid time"
            
            # Format: YY-MM-DD-hh-mm-ss
            year = digits[0] + digits[1]
            month = digits[2] + digits[3]
            day = digits[4] + digits[5]
            hour = digits[6] + digits[7]
            minute = digits[8] + digits[9]
            second = digits[10] + digits[11]
            
            # Handle year (assuming 2000s for years < 50, 1900s for years >= 50)
            year_int = int(year)
            century = "20" if year_int < 50 else "19"
            
            return f"{century}{year}-{month}-{day} {hour}:{minute}:{second}"
            
        except Exception as e:
            return f"Time error: {e}"
    
    def parse_extension_info(self, extension_bytes: bytes) -> Dict[str, Any]:
        """Parse extension information - IMPROVED VERSION"""
        extensions = {}
        pos = 0
        
        while pos < len(extension_bytes):
            if pos + 2 > len(extension_bytes):
                break
                
            extension_id = extension_bytes[pos]
            extension_length = extension_bytes[pos + 1]
            
            # Validate extension length
            if extension_length == 0 or pos + 2 + extension_length > len(extension_bytes):
                # Try to find next valid extension by scanning
                pos += 1
                continue
            
            extension_data = extension_bytes[pos + 2:pos + 2 + extension_length]
            
            try:
                if extension_id == 0x01:  # Mileage
                    if len(extension_data) >= 4:
                        extensions['mileage'] = int.from_bytes(extension_data[:4], byteorder='big') / 10.0
                
                elif extension_id == 0x30:  # CSQ
                    extensions['csq'] = extension_data[0]
                
                elif extension_id == 0x31:  # GPS satellites
                    extensions['gps_satellites'] = extension_data[0]
                
                elif extension_id == 0xF0:  # Base station
                    extensions['base_station'] = self.parse_base_station_info(extension_data)
                
                elif extension_id == 0xF2:  # Firmware version
                    try:
                        # Remove null bytes and decode
                        clean_data = bytes([b for b in extension_data if b != 0])
                        firmware = clean_data.decode('ascii', errors='ignore').strip()
                        extensions['firmware'] = firmware
                    except:
                        extensions['firmware'] = extension_data.hex()
                
                elif extension_id == 0xF6:  # Sensor info
                    extensions['sensor'] = self.parse_sensor_info(extension_data)
                
                elif extension_id == 0xF7:  # Battery info
                    extensions['battery'] = self.parse_battery_info(extension_data)
                
                elif extension_id == 0xF8:  # Device info
                    extensions['device_info'] = self.parse_device_info(extension_data)
                
                elif extension_id == 0xF9:  # Assistant info
                    extensions['assistant_info'] = self.parse_assistant_info(extension_data)
                
                elif extension_id == 0xF4:  # WiFi info
                    extensions['wifi'] = self.parse_wifi_info(extension_data)
                    
            except Exception as e:
                # Skip this extension but continue parsing others
                pass
            
            pos += 2 + extension_length
        
        return extensions
    
    def parse_base_station_info(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse base station information"""
        base_stations = []
        pos = 0
        
        # Each base station entry is 13 bytes
        while pos + 13 <= len(data):
            try:
                mcc = int.from_bytes(data[pos:pos+2], byteorder='big')
                mnc = int.from_bytes(data[pos+2:pos+4], byteorder='big')
                ci = int.from_bytes(data[pos+4:pos+8], byteorder='big')
                lac = int.from_bytes(data[pos+8:pos+10], byteorder='big')
                rssi = data[pos+12]  # RSSI is at position 12
                
                base_stations.append({
                    'mcc': mcc, 'mnc': mnc, 'ci': ci, 'lac': lac, 'rssi': rssi
                })
            except:
                pass
            
            pos += 13
        
        return base_stations
    
    def parse_sensor_info(self, data: bytes) -> Dict[str, Any]:
        """Parse sensor information"""
        if len(data) < 2:
            return {}
        
        result = {
            'trigger_event_type': data[0],
            'sensor_field_mask': data[1],
        }
        
        mask = data[1]
        pos = 2
        
        # Parse fields based on mask
        if (mask & 0x01) and pos + 2 <= len(data):  # Light
            result['light'] = int.from_bytes(data[pos:pos+2], byteorder='big')
            pos += 2
        
        if (mask & 0x02) and pos + 2 <= len(data):  # Temperature
            result['temperature'] = int.from_bytes(data[pos:pos+2], byteorder='big', signed=True) / 10.0
            pos += 2
        
        if (mask & 0x04) and pos + 2 <= len(data):  # Humidity
            result['humidity'] = int.from_bytes(data[pos:pos+2], byteorder='big') / 10.0
            pos += 2
        
        return result
    
    def parse_battery_info(self, data: bytes) -> Dict[str, Any]:
        """Parse battery information"""
        if len(data) >= 6:
            try:
                voltage = int.from_bytes(data[0:4], byteorder='big') / 1000.0
                charge_state = data[4]
                percentage = data[5]
                
                charge_states = {
                    0: 'Invalid', 1: 'Uncharged', 2: 'Charging', 
                    3: 'Full charging', 4: 'Abnormal'
                }
                
                return {
                    'voltage': round(voltage, 3),
                    'charge_state': charge_states.get(charge_state, 'Unknown'),
                    'percentage': percentage
                }
            except:
                pass
        return {}
    
    def parse_device_info(self, data: bytes) -> Dict[str, Any]:
        """Parse device information"""
        result = {}
        try:
            if len(data) >= 1:
                result['work_mode'] = data[0]
            if len(data) >= 9:
                result['imei'] = ''.join([f'{b:02x}' for b in data[1:9]])
            if len(data) >= 19:
                try:
                    result['part_number'] = data[19:29].decode('ascii', errors='ignore').strip('\x00')
                except:
                    pass
        except:
            pass
        return result
    
    def parse_assistant_info(self, data: bytes) -> Dict[str, Any]:
        """Parse assistant information"""
        result = {}
        try:
            if len(data) >= 2:
                mask = int.from_bytes(data[0:2], byteorder='big')
                pos = 2
                
                # Skip reserved fields based on mask
                if (mask & 0x01) and pos + 4 <= len(data):  # GNSS age
                    pos += 4
                if (mask & 0x02) and pos + 4 <= len(data):  # ACC on time
                    pos += 4
                if (mask & 0x04) and pos + 2 <= len(data):  # HDOP
                    pos += 2
                if (mask & 0x08) and pos + 6 <= len(data):  # GNSS time
                    pos += 6
                
                # Parse sampling and report intervals (bit 5)
                if (mask & 0x20) and pos + 8 <= len(data):
                    result['sampling_interval'] = int.from_bytes(data[pos:pos+4], byteorder='big')
                    result['report_interval'] = int.from_bytes(data[pos+4:pos+8], byteorder='big')
        except:
            pass
        return result
    
    def parse_wifi_info(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse WiFi information"""
        wifi_list = []
        pos = 0
        
        try:
            # WiFi format: [MAC(6) + RSSI(1)] for each AP
            while pos + 7 <= len(data):
                mac_bytes = data[pos:pos+6]
                rssi = data[pos+6]
                mac_address = ':'.join(f'{b:02x}' for b in mac_bytes).upper()
                wifi_list.append({'mac': mac_address, 'rssi': rssi})
                pos += 7
        except:
            pass
        
        return wifi_list

def main():
    st.set_page_config(page_title="New Gen Message Parser(7eX0200/0104)", layout="wide")
    
    st.title("New Gen Message Parser(7eX0200/0104)")
    st.markdown("---")
    
    # Initialize session state for column selection and parsed messages
    if 'selected_columns' not in st.session_state:
        st.session_state.selected_columns = [
            "Message Type", "Device ID", "Sequence Number", "Data Type", 
            "GNSS Fixed", "Latitude", "Longitude", "Time", "Data Buffered"
        ]
    
    if 'parsed_messages' not in st.session_state:
        st.session_state.parsed_messages = []
    
    # Create parser instance
    parser = JT1078Parser()
    
    # Sidebar for column selection
    with st.sidebar:
        st.subheader("📊 Columns Selected")
        
        # Select all checkbox
        select_all = st.checkbox("Select All", value=True, key="select_all")
        
        # Column selection checkboxes
        selected_columns = []
        for column in parser.all_columns:
            if st.checkbox(column, value=select_all, key=column):
                selected_columns.append(column)
        
        st.session_state.selected_columns = selected_columns
    
    # Input area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📥 Input Messages")
        messages_text = st.text_area(
            "Paste your Messages:",
            height=300,
            placeholder="Sep 3, 2025 12:57 PM PDT\n7e020000e4487064909541577d01000000001000000a023a5b6b0744aaaa00190000000025090319570130011f310106f00d0136019a0a14231000009f05bdf237414f56585f474c3230302d474c5f48312e325f454739313255474c41415230334131324d30385f56322e302e383a7632365f4253465f4e...\n\n7e0104001B4130503398280014FFDE040000F00F01010000F01001010000F01201050000F014011F8E\n\n7E8103002C593054480644FFEB060000F02301010000F0240200280000F0250200000000F028040000001E0000F0260200320000F02702000A8A7E",
            key="messages_input"
        )
    
    with col2:
        st.subheader("ℹ️ Instructions")
        st.info("""
        1. Paste messages with timestamps
        2. Include hex data (7e...7e)
        3. One message per line
        4. Click Parse button
        5. Supports message types:
           - 0x0200: Device Basic Information
           - 0x0104: Device Command Response(ACK)
        6. In parsed messages:
           - Time: Format is "UTC"
           - Light: Value in "mV"
           - Temperature: In "°C"
           - Humidity: In "%"     
        """)
    
    # Parse button
    if st.button("🚀 Parse Messages", type="primary", key="parse_button"):
        if messages_text.strip():
            with st.spinner("Parsing messages..."):
                parsed_messages = parser.parse_messages(messages_text)
                st.session_state.parsed_messages = parsed_messages
            
            if parsed_messages:
                st.success(f"✅ Parsed {len(parsed_messages)} messages!")
            else:
                st.error("❌ No valid messages found! Check message format.")
        else:
            st.warning("⚠️ Please paste messages!")
    
    # Display results if we have parsed messages
    if st.session_state.parsed_messages:
        # Create table data
        table_data = []
        for msg in st.session_state.parsed_messages:
            msg_type = msg.get('message_type', 'Unknown')
            row = {}
            
            # Add all possible columns with default values
            for col in parser.all_columns:
                row[col] = 'N/A'
            
            # Set message type
            row['Message Type'] = msg_type
            
            # Common fields
            row['Device ID'] = msg.get('device_id', 'N/A')
            row['Sequence Number'] = msg.get('sequence_number', 'N/A')
            
            if msg_type == '0x0200 - Device Basic Information':
                ext = msg.get('extension_info', {})
                base_stations = ext.get('base_station', [])
                wifi_list = ext.get('wifi', [])
                sensor = ext.get('sensor', {})
                battery = ext.get('battery', {})
                device_info = ext.get('device_info', {})
                assistant = ext.get('assistant_info', {})
                
                # Status fields
                status = msg.get('status', {})
                row['Data Type'] = "Real-time" if not status.get('buffered_data', False) else "Buffered"
                row['GNSS Fixed'] = "Yes" if status.get('gnss_fixed', False) else "No"
                #row['Data Sampled'] = "Yes" if status.get('sampled_data', False) else "No"
                #row['Data Buffered'] = "Yes" if status.get('buffered_data', False) else "No"
                row['Network Mode'] = status.get('network_mode_str', 'N/A')
                
                # Position fields
                row['Latitude'] = msg.get('latitude', 'N/A')
                row['Longitude'] = msg.get('longitude', 'N/A')
                #row['Altitude'] = msg.get('altitude', 'N/A')
                #row['Speed'] = msg.get('speed', 'N/A')
                #row['Direction'] = msg.get('direction', 'N/A')
                row['Time'] = msg.get('time', 'N/A')
                
                # Extension fields
                row['CSQ'] = ext.get('csq', 'N/A')
                row['GPS Satellites'] = ext.get('gps_satellites', 'N/A')
                
                # Base station info
                if base_stations:
                    bs_info = []
                    for bs in base_stations:  # Show ALL base stations
                        bs_str = f"MCC:{bs.get('mcc', 'N/A')}/MNC:{bs.get('mnc', 'N/A')}/LAC:{bs.get('lac', 'N/A')}/CI:{bs.get('ci', 'N/A')}"
                        bs_info.append(bs_str)
                    row['Base Station'] = " | ".join(bs_info)
                
                # WiFi info
                if wifi_list:
                    wifi_info = []
                    for wifi in wifi_list[:2]:  # Show first 2 WiFi APs
                        wifi_str = f"MAC:{wifi.get('mac', 'N/A')}/RSSI:{wifi.get('rssi', 'N/A')}"
                        wifi_info.append(wifi_str)
                    row['WiFi APs'] = " | ".join(wifi_info)
                    if len(wifi_list) > 2:
                        row['WiFi APs'] += f" (+{len(wifi_list)-2} more)"
                
                # Other extension fields
                row['Firmware'] = ext.get('firmware', 'N/A')
                row['Light'] = sensor.get('light', 'N/A')
                row['Temperature'] = sensor.get('temperature', 'N/A')
                row['Humidity'] = sensor.get('humidity', 'N/A')
                row['Battery Voltage'] = battery.get('voltage', 'N/A')
                row['Battery Percentage'] = battery.get('percentage', 'N/A')
                row['Battery Status'] = battery.get('charge_state', 'N/A')
                row['Sampling Interval'] = assistant.get('sampling_interval', 'N/A')
                row['Reporting Interval'] = assistant.get('report_interval', 'N/A')
                #row['IMEI'] = device_info.get('imei', 'N/A')
                #row['Work Mode'] = device_info.get('work_mode', 'N/A')
                #row['Part Number'] = device_info.get('part_number', 'N/A')
                #row['Mileage'] = ext.get('mileage', 'N/A')
            
            elif msg_type in ['0x0104 - Device Command Response(ACK)', '0x8103 - Configuration Commands Parameters']:
                #row['Response Sequence'] = msg.get('response_sequence', 'N/A')
                #row['Total Parameters'] = msg.get('total_parameters', 'N/A')
                
                parameters = msg.get('parameters', [])
                param_info = ""
                if parameters:
                    param_strings = []
                    for param in parameters[:3]:  # Show first 3 parameters
                        param_str = f"{param.get('name', 'Unknown')}: {param.get('value', 'N/A')}"
                        param_strings.append(param_str)
                    
                    param_info = " | ".join(param_strings)
                    if len(parameters) > 3:
                        param_info += f" (+{len(parameters)-3} more)"
                
                row['Parameters'] = param_info
            
            # Filter to only include selected columns
            filtered_row = {col: row[col] for col in st.session_state.selected_columns if col in row}
            table_data.append(filtered_row)
        
        # Display table
        st.subheader("📊 Parsed Messages")
        if table_data:
            df = pd.DataFrame(table_data)
            st.dataframe(df, use_container_width=True)
            
            # Download button
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name="parsed_messages.csv",
                mime="text/csv",
            )
        else:
            st.info("No data to display with the current column selection.")
    
    # Footer
    st.markdown("---")
    #st.caption("JT1078 Protocol Parser v1.0")

if __name__ == "__main__":
    main()