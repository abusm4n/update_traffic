# Update Traffic Analysis for IoT Devices



## First exract update-related_kewords,
This script processed the 34,586 pcaps files, reduce it to 6,315

src/keyword_occurance.py ~/update_traffic/dataset/ ~/update_traffic/dataset/update_related_pcaps.csv
For extracting update-related network traffics.
Found 6,315 network traffic, this took  4:02:53 hours.


## Exracting encrypted and unecrypted packets from the dataset 


python3 src/extract_http.py ~/update_traffic/dataset/ ~/update_traffic/extracted/foldername
For extracting http traffics from pcap files



python3 src/extract_all.py ~/update_traffic/imc19_dataset/ ~/update_traffic/dataset/extracted_all/





python3 src/analysis.py  ~/update_traffic/extracted/
For analzying extracted pcap











python3 src/check_true_updates.py ~/update_traffic/extracted_iot-data/




python3 src/generatecharts.py  ~/update_traffic/tls_iot-data/  ~/update_traffic/output/








#####

extracting 

./intl-iot/encryption/encryption.sh  ~/update_traffic/update_keywords/dataset/iot-data/uk/allure-speaker/android_lan_audio_off/2019-05-04_19:52:11.65s.pcap ~/update_traffic/update_keywords/dataset/sample.csv ~/update_traffic/update_keywords/dataset/sample.json




####
Entropy



####
Exract ecryption information, include:
Cipher suies and certificate: Examples
python3 src/ciphersuite.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/allure-speaker/2019-04-26_17:23:20.68s.json
Found 28 unique cipher suites:
  002f : Weak
  0033 : Weak
  0035 : Weak
  0039 : Weak
  003c : Weak
  003d : Weak
  0067 : Unknown
  006b : Unknown
  009c : Weak
  009d : Weak
  009e : Secure
  009f : Secure
  00ff : Insecure/Other
  c009 : Recommended
  c00a : Recommended
  c013 : Recommended
  c014 : Recommended
  c023 : Recommended
  c024 : Unknown
  c027 : Recommended
  c028 : Unknown
  c02b : Secure
  c02c : Secure
  c02f : Secure
  c030 : Secure
  cca8 : Secure
  cca9 : Secure
  ccaa : Secure

