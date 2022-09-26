# fusion_tinydtls
it's a project that coalescing confidential storage and DTLS in IoT device.

# CONTENTS 

This library contains functions and structures that can help
constructing a single-threaded UDP server with DTLS support in
C99. The following components are available:

* dtls
  Basic support for DTLS with pre-shared key mode.

* tests
  The subdirectory tests contains test programs that show how each
  component is used. 

# BUILDING

When using the code from the git repository at sourceforge, invoke
'autoreconf' to re-create the configure script. To build for Contiki,
place tinydtls into Contiki's apps directory and call 
  `./configure --with-contiki`.

After configuration, invoke make to build the library and associated
test programs. To add tinydtls as Contiki application, drop it into
the apps directory and add the following line to your Makefile:

  `APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls`


# Code description

Main function is under `example/contiki/sensor.c`, line number 380 `Process_thread` function.

- sensor.c는 데이터를 수집하고 FDTLS를 수행하는 IoT 디바이스 코드. 반대로 reciever.c는 이런 센서와 통신을 수행하기 위한 상대방 device를 위한 코드 
- FDTLS에서는 초기에 virtual peer를 생성해야함. 이를 위해 create_vitaul_peer 함수를 호출 (415 라인)
- virtual peer를 사용해 추후 datagram을 암호화하는데 필요한 key block을 생성: calculate_key_block_self 함수 호출 (420 라인). DTLS key block의 구조와 FDTLS의 구조는 첨부 피피티의 9페이지 참고. FDTLS에서는 서버 키는 항상 일정한 값을 생성하도록하고, 클라이언트는 연결 클라이언트 개별로 독립적인 랜덤 키값을 생성. virtual_peer를 통해 미리 서버키를 생성하는 것이 목표이며 이렇게 생성된 서버 키를 통해 수집된 데이터를 다른 클라이언트와 연결되기 전에 미리 암호화할 수 있음 
- cfs_prepare_data에서는 위의 key block을 사용하여 미리 암호화된 데이터를 준비함. (본래 DTLS에서는 상대방과 handshake를 맺고 암호화된 데이터를 생성하여 전송하지만 FDTLS에서는 virtual peer를 통해 이러한 과정을 생략하고, 수집한 데이터들에 대해 미리 암호화과정을 수행하여 저장공간에 암호화된 데이터를 저장. 추후 상대방이 등장했을 때 이 암호화된 데이터를 전송). #ifdef FDTLS를 보면 알 수 있듯, FDTLS가 선언됐을 때와 선언되지 않았을 때 수행하는 동작이 다름. FDTLS가 선언되지 않았을 때는 노멀한 DTLS 동작과정을 수행 
- cfs_preapre_data에서 실질적으로 데이터를 암호화하는 것은 dtls_encrypt_data 함수. 이 함수는 dtls.c에 정의되어 있음. 앞서 가상 피어를 생성하고 이 피어와 handshake과정을 수행하면서 vir_sess에 가상 피어와의 연결 정보, key block이 포함되어 있음. 이 vir_sess 파라미터를 cfs_prepare_data와 dtls_encrypt_data에 전달함으로써 data를 암호화 
- cfs_prepare_data에서 cfs_write는 저장공간에 데이터를 쓰는 과정. FDTLS이 선언됐을 때는 암호화된 데이터를 저장, 아닐 경우에는 일반 평문을 저장
- 423번쨰 라인 while문에서는 리시버와 통신을 수행. 이벤트 발생 시 dtls_handle_read 함수를 수행. 이는 dtls_handle_message를 호출 (dtls.c 참고). 해당 함수에선 연결되지 않은 peer의 경우 handshake를 수행하고, 이미 연결된 피어의 경우 암호화된 데이터를 복호화하여 출력 
- FDTLS는 handshake 과정에서 dtls_prf가 아닌 dtls_prf_custom 함수를 사용 (dtls.c의 750라인). 이 함수는 tinydtls-crypto.c에 정의되어 있으며, server key 파트는 랜덤 시드 없이 항상 일정한 key 값을 생성해내고 client key 값만 random seed를 사용하여 클라이언트 개별로 random한 시드를 생성하도록 함. 이는 첨부 ppt의 10페이지 참고 