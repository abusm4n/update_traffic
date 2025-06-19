# Update Traffic Analysis for IoT Devices





python3 src/extract_http.py ~/update_traffic/dataset/ ~/update_traffic/extracted/foldername
For extracting http traffics from pcap files






python3 src/analysis.py  ~/update_traffic/extracted/
For analzying extracted pcap


python3 src/generatecharts.py  ~/update_traffic/extracted/ ~/update_traffic/output/
Loaded packet JSON
Loaded metadata pickle
Saved MIME type chart to /home/ab/update_traffic/output/df_mime_plot.png
{'power': 0, 'android_lan_on': 0, 'android_lan_dim': 0, 'android_lan_off': 0, 'local_menu': 0, 'android_wan_on': 0, 'local_on': 0, 'android_wan_color': 0, 'alexa_unlock': 0, 'alexa_color': 1, 'local_off': 0, 'android_wan_off': 0, 'alexa_off': 1, 'local_start': 0, 'local_stop': 0, 'alexa_on': 1, 'android_wan_watch': 0, 'android_lan_recording': 0, 'android_wan_recording': 0, 'android_lan_watch': 0, 'android_lan_photo': 0, 'android_lan_color': 0, 'android_wan_audio_on': 0, 'android_lan_audio_off': 0, 'android_wan_dim': 0, 'alexa_dim': 1, 'local_volume': 0, 'android_lan_audio_on': 0, 'local_voice': 0, 'android_wan_photo': 0, 'android_wan_audio_off': 0, 'android_lan_menu': 3, 'local_ring': 0, 'local_move': 0, 'local_button': 0, 'android_lan_remote': 0, 'google_on': 0, 'android_lan_lock': 0, 'android_wan_lock': 0, 'google_off': 0, 'android_lan_unlock': 0, 'android_wan_unlock': 0, 'voice': 0, 'volume': 0, 'google_color': 0, 'android_wan_remote': 0, 'alexa_lock': 0, 'alexa_stop': 0, 'cloudcam': 0, 'google-home-mini2': 0, 't-echodot': 18, 'appletv': 0, 'smartthings-hub': 0, 'washer': 0, 'amcrest-cam-wired': 8, 'brewer': 0, 't-wemo-plug': 6, 'dlink-mov': 0, 'echoplus': 0, 'wansview-cam-wired': 0, 'echospot': 0, 'lgtv-wired': 4, 'dryer': 0, 'xiaomi-hub': 0, 'echodot': 8, 't-philips-hub': 32, 'zmodo-doorbell': 0, 'firetv': 0, 'roku-tv': 0, 'samsungtv-wired': 0, 'bulb1': 0, 'yi-camera': 0, 'uk-vpn': 0, 'uk': 0, 'philips-bulb': 0, 'xiaomi-strip': 0, 'google-home-mini': 0, 'insteon-hub': 0, 'xiaomi-ricecooker': 0, 'fridge': 0}
Saved update endpoint chart to /home/ab/update_traffic/output/df_meta_update_counts.png








python3 src/check_true_updates.py ~/update_traffic/extracted_iot-data/




python3 src/generatecharts.py  ~/update_traffic/tls_iot-data/  ~/update_traffic/output/





src/keyword_occurance.py ~/update_traffic/dataset/ ~/update_traffic/keywords/matching_pcaps.csv
For extracting update-related network traffics.
Found 6,315 network traffic, this took  4:02:53 hours.




#####

extracting 

./intl-iot/encryption/encryption.sh  ~/update_traffic/update_keywords/dataset/iot-data/uk/allure-speaker/android_lan_audio_off/2019-05-04_19:52:11.65s.pcap ~/update_traffic/update_keywords/dataset/sample.csv ~/update_traffic/update_keywords/dataset/sample.json







####
Exract ecryption information, include:
Cipher suies and certificate:
python3 src/tls_cert.py  ~/update_traffic/update_keywords/dataset/iot-data/uk/allure-speaker/android_lan_audio_off/2019-05-04_19:52:11.65s.pcap



