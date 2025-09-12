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
Cipher suies and certificate: Examples
python3 src/ciphersuite.py /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-04-26_14\:06\:00.202s.json 
Cipher suite category counts:
  Secure: 70
  Recommended: 42
  Weak: 56
  Insecure: 7
  Unknown: 130

  ## for neested folders

  python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-spea
ker
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-04-26_13:44:16.229s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-05-01_09:54:19.65s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-04-27_18:30:49.66s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-05-04_01:55:49.65s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-05-06_14:02:50.68s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-05-03_15:51:30.65s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-04-26_14:06:00.202s.json...
Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-04-26_13:57:10.183s.json...

Summary of categories:
  Secure: 260
  Unknown: 410
  Recommended: 156
  Weak: 208
  Insecure: 26

Unique cipher suites found:
  c02f : Secure (45 occurrences)
  c030 : Secure (33 occurrences)
  c02c : Secure (26 occurrences)
  009f : Secure (26 occurrences)
  cca9 : Secure (26 occurrences)
  cca8 : Secure (26 occurrences)
  ccaa : Secure (26 occurrences)
  c02b : Secure (26 occurrences)
  009e : Secure (26 occurrences)
  c024 : Unknown (26 occurrences)
  c028 : Unknown (26 occurrences)
  006b : Unknown (26 occurrences)
  c023 : Recommended (26 occurrences)
  c027 : Recommended (26 occurrences)
  0067 : Unknown (26 occurrences)
  c00a : Recommended (26 occurrences)
  c014 : Recommended (26 occurrences)
  0039 : Weak (26 occurrences)
  c009 : Recommended (26 occurrences)
  c013 : Recommended (26 occurrences)
  0033 : Weak (26 occurrences)
  009d : Weak (26 occurrences)
  009c : Weak (26 occurrences)
  003d : Weak (26 occurrences)
  003c : Weak (26 occurrences)
  0035 : Weak (26 occurrences)
  002f : Weak (26 occurrences)
  00ff : Insecure (26 occurrences)
  00a3 : Unknown (9 occurrences)
  c0af : Unknown (9 occurrences)
  c0ad : Unknown (9 occurrences)
  c0a3 : Unknown (9 occurrences)
  c09f : Unknown (9 occurrences)
  00a2 : Unknown (9 occurrences)
  c0ae : Unknown (9 occurrences)
  c0ac : Unknown (9 occurrences)
  c0a2 : Unknown (9 occurrences)
  c09e : Unknown (9 occurrences)
  006a : Unknown (9 occurrences)
  c073 : Unknown (9 occurrences)
  c077 : Unknown (9 occurrences)
  00c4 : Unknown (9 occurrences)
  00c3 : Unknown (9 occurrences)
  0040 : Unknown (9 occurrences)
  c072 : Unknown (9 occurrences)
  c076 : Unknown (9 occurrences)
  00be : Unknown (9 occurrences)
  00bd : Unknown (9 occurrences)
  0038 : Unknown (9 occurrences)
  0088 : Unknown (9 occurrences)
  0087 : Unknown (9 occurrences)
  0032 : Unknown (9 occurrences)
  0045 : Unknown (9 occurrences)
  0044 : Unknown (9 occurrences)
  c0a1 : Unknown (9 occurrences)
  c09d : Unknown (9 occurrences)
  c0a0 : Unknown (9 occurrences)
  c09c : Unknown (9 occurrences)
  00c0 : Unknown (9 occurrences)
  00ba : Unknown (9 occurrences)
  0084 : Unknown (9 occurrences)
  0041 : Unknown (9 occurrences)
