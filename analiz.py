import requests
import getpass
import json
import pandas as pd
import datetime
import os
import requests_ntlm
import urllib3
import math
import time

urllib3.disable_warnings()

def create_session():
    session = requests.Session()
    session.verify = False  # SSL doğrulamasını devre dışı bırakmak için
    return session

def login_with_ntlm(session, epm_server_address, epm_username, epm_password):
    login_data = {
        "ApplicationID": "Irrelevant"
    }

    login_api_url = f"{epm_server_address}/EPM/API/Auth/Windows/logon"
    response = session.post(login_api_url, json=login_data, auth=requests_ntlm.HttpNtlmAuth(epm_username, epm_password))

    if response.status_code == 200:
        response_data = response.json()
        manager_url = epm_server_address
        epm_authentication = response_data.get("EPMAuthenticationResult")
        return manager_url, epm_authentication
    else:
        return None, None
        
def create_headers(epm_authentication):
    return {
        "VFUser": epm_authentication,
        "Content-Type": "application/json",
    }

def fetch_sets(session, manager_url, headers):
    api_url = f"{manager_url}/EPM/API/Sets"
    response = session.get(api_url, headers=headers)

    if response.status_code == 200:
        api_response_data = response.json()
        sets_count = api_response_data.get("SetsCount")
        sets_list = api_response_data.get("Sets")
        return sets_count, sets_list
    else:
        return None, None

def fetch_pc_list_by_set(session, manager_url, headers, selected_set, use_ntlm=False, page_size=5000):
    pc_list = []
    api_url = f"{manager_url}/EPM/API/Sets/{selected_set.get('Id')}/Computers"

    # Toplam PC sayısını al
    response = session.get(api_url, headers=headers, verify=False if use_ntlm else True)
    if response.status_code == 200:
        pc_list_data = response.json()
        total_count = pc_list_data.get("TotalCount")
        print("Set Adı :", selected_set.get('Name'))
        print("Toplam PC Sayısı: ", total_count)
        if total_count is None:
            return None

        # Toplam sayfa sayısını hesapla
        total_pages = math.ceil(total_count / page_size)

        # Her sayfayı çek
        for page in range(1, total_pages + 1):
            offset = (page - 1) * page_size +1
            time.sleep(3)
            page_api_url = f"{api_url}?offset={offset}&limit={page_size}"
            print(page_api_url)
            response = session.get(page_api_url, headers=headers, verify=False if use_ntlm else True)
            print(response)
            if response.status_code == 200:
                page_pc_list_data = response.json()
                page_pc_list = page_pc_list_data.get("Computers")
                if page_pc_list:
                    pc_list.extend(page_pc_list)
                else:
                    break  # Sayfa boşsa sonraki sayfaları çekmeye gerek yok

        # Son sayfadaki kalan kayıt sayısını hesapla ve limiti ayarla
        remaining_records = total_count % page_size
        if remaining_records > 0:
            offset = total_pages * page_size
            time.sleep(3)
            last_page_api_url = f"{api_url}?offset={offset}&limit={remaining_records}"
            print(last_page_api_url)
            response = session.get(last_page_api_url, headers=headers, verify=False if use_ntlm else True)
            print(response)
            if response.status_code == 200:
                last_page_pc_list_data = response.json()
                last_page_pc_list = last_page_pc_list_data.get("Computers")
                if last_page_pc_list:
                    pc_list.extend(last_page_pc_list)

    return pc_list

def fetch_all_pc_lists(session, manager_url, headers, sets_list):
    all_pc_list = []

    for selected_set in sets_list:
        pc_list = fetch_pc_list_by_set(session, manager_url, headers, selected_set)

        if pc_list:
            for pc in pc_list:
                pc["Set Adı"] = selected_set.get("Name")
            all_pc_list.extend(pc_list)

    return all_pc_list

def save_to_excel(file_name, data, output_dir="."):
    file_path = os.path.join(output_dir, f"{file_name}.xlsx")
    data.to_excel(file_path, index=False)
    print(f"{file_path} adlı Excel dosyası oluşturuldu.")

def main():
    session = create_session()

    epm_server_address = input("EPM Sunucu Adresi: ")
    epm_username = input("EPM Kullanıcı Adı: ")
    epm_password = getpass.getpass("EPM Kullanıcı Şifresi: ")

    manager_url, epm_authentication = login_with_ntlm(session, epm_server_address, epm_username, epm_password)

    if manager_url and epm_authentication:
        headers = create_headers(epm_authentication)
        sets_count, sets_list = fetch_sets(session, manager_url, headers)

        if sets_count is not None and sets_list:
            print("Set Sayısı:", sets_count)
            print("Set Listesi:")

            for i, set_data in enumerate(sets_list):
                print(f"{i + 1}. {set_data.get('Name')}")

            selected_option = int(input("Seçenekleri belirle:\n1. Tüm setlerin pc listesini al ve dosyaya yaz\n2. Tek bir setin pc listesini al\nSeçiminiz: "))

            if selected_option == 1:
                output_dir = input("Pc listesini kaydetmek istediğiniz dizini girin (varsayılan: mevcut dizin): ")
                if not output_dir:
                    output_dir = "."

                all_pc_list = fetch_all_pc_lists(session, manager_url, headers, sets_list)

                if all_pc_list:
                    excel_file_name = f"all_sets_pc_list_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
                    save_to_excel(excel_file_name, pd.DataFrame(all_pc_list), output_dir)
                    print(f"Tüm setlerin pc listesi Excel dosyası '{output_dir}' dizinine yazıldı.")
                else:
                    print("Pc listesi alınamadı.")

            elif selected_option == 2:
                selected_set_index = int(input("Hangi setin üye pc listesini almak istersiniz? (Set numarasını girin): ")) - 1

                if 0 <= selected_set_index < len(sets_list):
                    selected_set = sets_list[selected_set_index]

                    output_dir = input("Pc listesini kaydetmek istediğiniz dizini girin (varsayılan: mevcut dizin): ")
                    if not output_dir:
                        output_dir = "."

                    pc_list = fetch_pc_list_by_set(session, manager_url, headers, selected_set)

                    if pc_list:
                        file_name = f"{selected_set.get('Name')}pc_list{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
                        save_to_excel(file_name, pd.DataFrame(pc_list), output_dir)
                        print(f"{selected_set.get('Name')} setinin pc listesi '{output_dir}' dizinine yazıldı.")
                    else:
                        print(f"{selected_set.get('Name')} setinin pc listesi alınamadı.")
                else:
                    print("Geçersiz set numarası.")
        else:
            print("API isteği başarısız oldu.")

    else:
        print("Giriş başarısız oldu.")

if __name__ == "__main__":
    main()
