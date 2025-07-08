import json
import xml.etree.ElementTree as ET
from uuid import uuid4
import logging
import os
from datetime import datetime
import sys

def setup_logging():
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Setup logging with timestamp in filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f'logs/converter_{timestamp}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_filename

def safe_upper(text):
    """ASCII karakterler için güvenli büyük harf dönüşümü"""
    if not text:
        return text
    # Sadece ASCII karakterleri büyük harfe çevir, Türkçe karakterleri olduğu gibi bırak
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr(ord(char) - 32)  # ASCII küçük → büyük
        else:
            result += char  # Diğer karakterleri olduğu gibi bırak
    return result

def get_conversion_mode():
    """Kullanıcıdan dönüştürme modunu sor"""
    print("\nVFP ApplicationGroup'ları nasıl dönüştürmek istiyorsunuz?")
    print("1. Sadece ApplicationGroup olarak (PolicyType: 14)")
    print("2. Policy olarak (PolicyType: 11) - Güvenlik politikası")
    print("3. Hem ApplicationGroup hem de Policy oluştur")
    
    while True:
        choice = input("Seçiminizi yapın (1-3): ").strip()
        if choice in ['1', '2', '3']:
            return int(choice)
        print("Geçersiz seçim! Lütfen 1, 2 veya 3 girin.")

def get_application_type(element_tag):
    # Application type mapping
    type_map = {
        'Executable': 3,
        'Dll': 21,
        'MSI': 5,
        'MSU': 6,
        'Admintask': 8,
        'ActiveXInstall': 9,
        'COM': 15,
        'Script': 4  # Script için PowerShell type
    }
    return type_map.get(element_tag, 3)

def get_compare_as_value(compare_as_text):
    # CompareAs mapping
    compare_map = {
        'exact': 0,
        'contains': 1,
        'wildcard': 2,
        'regex': 3
    }
    return compare_map.get(compare_as_text.lower(), 0)

def convert_patterns(element):
    patterns = {}
    
    # Convert FileName if exists
    filename = element.find('FileName')
    if filename is not None:
        patterns['FILE_NAME'] = {
            '@type': 'FileName',
            'content': filename.text,
            'caseSensitive': filename.get('caseSensitive', 'False').lower() == 'true',
            'compareAs': get_compare_as_value(filename.get('compareAs', 'exact')),
            'fileSize': 0,
            'hash': '',
            'hashAlgorithm': '',
            'isEmpty': False,
            'hashSHA256': ''
        }
    
    # Convert Location if exists
    location = element.find('Location')
    if location is not None:
        patterns['LOCATION'] = {
            '@type': 'Location',
            'content': location.text,
            'caseSensitive': location.get('caseSensitive', 'False').lower() == 'true',
            'withSubfolders': True,
            'isEmpty': False
        }
    
    # Convert Owner if exists - Tüm element türleri için OWNER pattern'i
    owner = element.find('Owner')
    if owner is not None:
        patterns['OWNER'] = {
            '@type': 'AdAccounts',
            'accounts': [{
                'name': safe_upper(owner.text),  # Güvenli büyük harf dönüşümü
                'sid': '',
                'accountType': 'SINGLE'
            }],
            'isEmpty': False
        }
    
    # Script elementleri için ek pattern'ler
    if element.tag == 'Script':
        # LOCATION_TYPE pattern'i
        patterns['LOCATION_TYPE'] = {
            '@type': 'LocationType',
            'locationType': 'FIXED',
            'isEmpty': False
        }
    
    # DLL elementleri için OWNER pattern'i
    if element.tag == 'Dll':
        owner = element.find('Owner')
        if owner is not None:
            patterns['OWNER'] = {
                '@type': 'AdAccounts',
                'accounts': [{
                    'name': owner.text,
                    'sid': '',
                    'accountType': 'SINGLE'
                }],
                'isEmpty': False
            }
    
    # Convert FileVerInfo elements
    for file_info in element.findall('FileVerInfo'):
        info_name = file_info.get('name')
        if info_name == 'ProductName':
            patterns['PRODUCT_NAME'] = {
                '@type': 'FileInfo',
                'elementName': 'FileVerInfo',
                'attributeInfoName': 'ProductName',
                'isEmpty': False,
                'content': file_info.text if file_info.text else '',
                'compareAs': get_compare_as_value(file_info.get('compareAs', 'exact')),
                'caseSensitive': file_info.get('caseSensitive', 'True').lower() == 'true'
            }
        elif info_name == 'FileDescription':
            patterns['FILE_DESCRIPTION'] = {
                '@type': 'FileInfo',
                'elementName': 'FileVerInfo',
                'attributeInfoName': 'FileDescription',
                'isEmpty': False,
                'content': file_info.text if file_info.text else '',
                'compareAs': get_compare_as_value(file_info.get('compareAs', 'exact')),
                'caseSensitive': file_info.get('caseSensitive', 'True').lower() == 'true'
            }
        elif info_name == 'CompanyName':
            patterns['COMPANY_NAME'] = {
                '@type': 'FileInfo',
                'elementName': 'FileVerInfo',
                'attributeInfoName': 'CompanyName',
                'isEmpty': False,
                'content': file_info.text if file_info.text else '',
                'compareAs': get_compare_as_value(file_info.get('compareAs', 'exact')),
                'caseSensitive': file_info.get('caseSensitive', 'True').lower() == 'true'
            }

    # Convert AdminTask patterns
    admin_tasks = element.findall('AdminTask')
    if admin_tasks:
        task_ids = []
        for task in admin_tasks:
            task_id = task.get('id')
            if task_id:
                task_ids.append(int(task_id))
        
        if task_ids:
            patterns['ADMIN_TASK_ID'] = {
                '@type': 'WinAdminTask',
                'taskIds': sorted(task_ids),
                'isEmpty': False
            }

    # Convert Publisher if exists
    publisher = element.find('Publisher')
    if publisher is not None and publisher.text and publisher.text.strip():
        patterns['PUBLISHER'] = {
            '@type': 'Publisher',
            'separator': ';',
            'caseSensitive': publisher.get('caseSensitive', 'True').lower() == 'true',
            'content': publisher.text.strip(),
            'signatureLevel': 2,  # Specific - content var ise
            'compareAs': get_compare_as_value(publisher.get('compareAs', 'exact')),
            'isEmpty': False
        }
    elif publisher is not None:
        # Publisher elementi var ama content boş ise
        patterns['PUBLISHER'] = {
            '@type': 'Publisher',
            'separator': ';',
            'caseSensitive': publisher.get('caseSensitive', 'True').lower() == 'true',
            'content': '',
            'signatureLevel': 1,  # Any - content boş ise
            'compareAs': get_compare_as_value(publisher.get('compareAs', 'exact')),
            'isEmpty': True
        }

    # Convert version information - MSI'lar için version pattern'i yok
    if element.tag != 'MSI':
        min_version = element.get('minVersion')
        max_version = element.get('maxVersion')
        if min_version:
            patterns['FILE_VERSION'] = {
                '@type': 'VersionRange',
                'minVersion': min_version,
                'maxVersion': max_version if max_version else min_version,
                'isEmpty': False
            }
        
        # Convert product version information - MSI'lar için product version da yok
        min_product_version = element.get('minProductVersion')
        max_product_version = element.get('maxProductVersion')
        if min_product_version:
            patterns['PRODUCT_VERSION'] = {
                '@type': 'VersionRange',
                'minVersion': min_product_version,
                'maxVersion': max_product_version if max_product_version else min_product_version,
                'isEmpty': False
            }

    return patterns

def convert_element_to_application(element):
    app_type = get_application_type(element.tag)
    patterns = convert_patterns(element)
    
    # VFP'deki targetId'yi kullan
    target_id = element.get('targetId')
    app_id = target_id if target_id else str(uuid4())
    
    logging.debug(f'Converting {element.tag} with type {app_type}, targetId: {target_id}')

    # Get boolean attributes
    inheritable = element.get('inheritable', 'False').lower() == 'true'
    restrict_file_dlg = element.get('restrictFileDlg', 'True').lower() == 'true'
    
    # internalDescription'ı al
    internal_description = element.find('internalDescription')
    
    description_parts = []
    if internal_description is not None and internal_description.text:
        description_parts.append(internal_description.text)
    
    description_text = '\n'.join(description_parts)

    return {
        'id': app_id,
        'internalId': 0,
        'applicationType': app_type,
        'displayName': '',
        'description': description_text,
        'patterns': patterns,
        'applicationGroupId': '00000000-0000-0000-0000-000000000000',
        'internalApplicationGroupId': 0,
        'includeInMatching': True,
        'accountId': '00000000-0000-0000-0000-000000000000',
        'childProcess': inheritable,
        'restrictOpenSaveFileDialog': restrict_file_dlg,
        'securityTokenId': '00000000-0000-0000-0000-000000000001',
        'protectInstalledFiles': False
    }

def parse_policy_targets(root):
    """VFP'deki policy target bilgilerini parse et"""
    policy_targets = {}
    
    # GpoPolicies bölümünü parse et
    gpo_policies = root.find('.//GpoPolicies')
    if gpo_policies is not None:
        for policy in gpo_policies.findall('Policy'):
            gpid = policy.get('gpid')
            action = policy.get('action', '1')
            name = policy.get('name', '')
            
            targets = policy.find('Targets')
            target_app_groups = []
            if targets is not None:
                for app_group in targets.findall('ApplicationGroup'):
                    target_app_groups.append(app_group.get('id'))
            
            # UserGroupList'i parse et
            target_users = []
            user_group_list = policy.find('UserGroupList')
            if user_group_list is not None:
                for user in user_group_list.findall('User'):
                    user_info = {
                        'sid': user.get('SID', ''),
                        'name': user.text or '',
                        'display_name': user.get('internalDisplayName', ''),
                        'type': user.get('internalType', '1')
                    }
                    target_users.append(user_info)
            
            policy_targets[gpid] = {
                'name': name,
                'action': int(action),
                'target_app_groups': target_app_groups,
                'target_users': target_users
            }
    
    # PolicyDescriptions bölümünü parse et
    policy_descriptions = root.find('.//PolicyDescriptions')
    if policy_descriptions is not None:
        for policy in policy_descriptions.findall('Policy'):
            gpid = policy.get('gpid')
            if gpid in policy_targets:
                all_computers = policy.find('AllComputers')
                if all_computers is not None:
                    policy_targets[gpid]['all_computers'] = all_computers.text.lower() == 'true'
                else:
                    policy_targets[gpid]['all_computers'] = False
    
    return policy_targets

def convert_vfp_to_epmp(vfp_content, conversion_mode):
    root = ET.fromstring(vfp_content)
    logging.info('Successfully parsed XML content')
    
    # Policy target bilgilerini parse et
    policy_targets = parse_policy_targets(root)
    logging.info(f'Found {len(policy_targets)} policy targets')
    
    # Find all application groups
    app_groups = root.find('.//ApplicationGroups')
    if app_groups is None:
        logging.error('No ApplicationGroups found in the XML')
        return None
    
    # Convert each application group
    policies = []
    app_groups_list = []
    
    for app_group in app_groups.findall('ApplicationGroup'):
        applications = []
        group_name = app_group.get('name', 'Unknown Group')
        group_description = app_group.get('description', '')
        group_id = app_group.get('id', str(uuid4()))  # VFP'den group ID'sini al
        
        logging.info(f'Processing application group: {group_name}')
        
        # Convert all types of applications
        for element_type in ['Executable', 'Dll', 'MSI', 'MSU', 'ActiveXInstall', 'COM', 'Script']:
            elements = app_group.findall(element_type)
            if elements:
                logging.info(f'Found {len(elements)} {element_type} elements in group {group_name}')
                for element in elements:
                    applications.append(convert_element_to_application(element))
        
        if not applications:
            logging.warning(f'No applications found in group {group_name}')
            continue
        
        # Policy description'ı oluştur (Owner'ları pattern'lerde olduğu için policy description'ına eklemeyelim)
        policy_description_parts = []
        if group_description:
            policy_description_parts.append(group_description)
        else:
            policy_description_parts.append(f"Application group: {group_name}")
        
        policy_description = '\n'.join(policy_description_parts)
        
        # VFP'deki policy target bilgilerini kontrol et
        target_policy = None
        for gpid, target_info in policy_targets.items():
            if group_id in target_info['target_app_groups']:
                target_policy = target_info
                break
        
        # Target policy'den bilgileri al
        is_all_computers = True
        policy_action = 1
        executors = []
        accounts = []
        
        if target_policy:
            is_all_computers = target_policy.get('all_computers', True)
            policy_action = target_policy.get('action', 1)
            
            # Target users'ları Accounts'a ekle
            for user_info in target_policy.get('target_users', []):
                if user_info['type'] == '2':  # Group
                    account_type = 7
                elif '\\' in user_info['name']:  # Domain user
                    account_type = 6
                else:  # Local user
                    account_type = 1
                
                accounts.append({
                    'Sid': user_info['sid'],
                    'AccountType': account_type,
                    'DisplayName': user_info['name'],
                    'SamName': user_info['name']
                })
            
            # EPMP import fix: AllComputers=false ama sadece user targeting varsa All Computers'a çevir
            if not is_all_computers and accounts and not executors:
                logging.warning(f'Policy {group_name} has user targeting but no computer targeting. Converting to All Computers for EPMP compatibility.')
                is_all_computers = True
            
            logging.info(f'Found target policy for {group_name}: All Computers={is_all_computers}, Action={policy_action}, Accounts={len(accounts)}')
        else:
            logging.warning(f'No target policy found for {group_name}, using defaults')

        # Conversion mode'a göre işlem yap
        if conversion_mode == 1:  # Sadece ApplicationGroup
            app_group_obj = {
                'Id': group_id,
                'Name': group_name,
                'PolicyType': 14,
                'Description': group_description,
                'LinkedAgentPolicies': [],
                'Applications': applications
            }
            app_groups_list.append(app_group_obj)
            logging.info(f'Created ApplicationGroup for {group_name} with {len(applications)} applications')
            
        elif conversion_mode == 2:  # Sadece Policy
            policy = {
                'Id': group_id,
                'Name': group_name,
                'PolicyType': 11,
                'Action': policy_action,
                'Description': policy_description,
                'LinkedAgentPolicies': [{'Id': group_id, 'InternalId': 0, 'PolicyType': 3}],
                'Executors': executors,
                'Accounts': accounts,
                'IncludeADComputerGroups': [],
                'ExcludeADComputerGroups': [],
                'IncludeAccounts': {
                    'CollectionId': '00000000-0000-0000-0000-000000000000',
                    'CollectionName': '',
                    'Operator': 0,
                    'UserGroupCollection': [],
                    'SelectedAccountCollection': []
                },
                'ExcludeAccounts': {
                    'CollectionId': '00000000-0000-0000-0000-000000000000',
                    'CollectionName': '',
                    'Operator': 0,
                    'UserGroupCollection': [],
                    'SelectedAccountCollection': []
                },
                'Audit': False,
                'Activation': {
                    'ActivateDate': None,
                    'DeactivateDate': None,
                    'Scheduler': None,
                    'AutoDelete': False
                },
                'Priority': 40,
                'RecordAuditVideo': False,
                'PreviouslyAppGroup': False,
                'ConditionalEnforcement': [],
                'AccessControl': None,
                'IsActive': True,
                'IsAppliedToAllComputers': is_all_computers,
                'Applications': applications,
                'UIAuditVideo': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'AuditVideoConfirmation'},
                'UIAuditVideoError': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'AuditVideoLowDisk'},
                'UIAuditVideoInit': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'AuditVideoNotify'},
                'UIOnStart': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'},
                'UIOnStartAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'},
                'UIReplaceUacAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'},
                'UIReplaceUAC': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'}
            }
            policies.append(policy)
            logging.info(f'Created Policy for {group_name} with {len(applications)} applications')
            
        elif conversion_mode == 3:  # Hem ApplicationGroup hem Policy
            # ApplicationGroup oluştur
            app_group_obj = {
                'Id': group_id,
                'Name': group_name,
                'PolicyType': 14,
                'Description': group_description,
                'LinkedAgentPolicies': [],
                'Applications': applications
            }
            app_groups_list.append(app_group_obj)
            
            # Policy oluştur
            policy_id = str(uuid4())
            policy = {
                'Id': policy_id,
                'Name': f"Policy for {group_name}",
                'PolicyType': 11,
                'Action': policy_action,
                'Description': f"Policy using ApplicationGroup: {group_name}",
                'LinkedAgentPolicies': [{'Id': policy_id, 'InternalId': 0, 'PolicyType': 3}],
                'Executors': executors,
                'Accounts': accounts,
                'IncludeADComputerGroups': [],
                'ExcludeADComputerGroups': [],
                'IncludeAccounts': {
                    'CollectionId': '00000000-0000-0000-0000-000000000000',
                    'CollectionName': '',
                    'Operator': 0,
                    'UserGroupCollection': [],
                    'SelectedAccountCollection': []
                },
                'ExcludeAccounts': {
                    'CollectionId': '00000000-0000-0000-0000-000000000000',
                    'CollectionName': '',
                    'Operator': 0,
                    'UserGroupCollection': [],
                    'SelectedAccountCollection': []
                },
                'Audit': False,
                'Activation': {
                    'ActivateDate': None,
                    'DeactivateDate': None,
                    'Scheduler': None,
                    'AutoDelete': False
                },
                'Priority': 40,
                'RecordAuditVideo': False,
                'PreviouslyAppGroup': False,
                'ConditionalEnforcement': [],
                'AccessControl': None,
                'IsActive': True,
                'IsAppliedToAllComputers': is_all_computers,
                'Applications': [{
                    'id': group_id,
                    'applicationType': 2,
                    'displayName': group_name,
                    'description': group_description,
                    'patterns': {},
                    'restrictOpenSaveFileDialog': False,
                    'protectInstalledFiles': False
                }],
                'UIAuditVideo': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'AuditVideoConfirmation'},
                'UIAuditVideoError': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'AuditVideoLowDisk'},
                'UIAuditVideoInit': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'AuditVideoNotify'},
                'UIOnStart': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'},
                'UIOnStartAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'},
                'UIReplaceUacAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'},
                'UIReplaceUAC': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'StartAlert'}
            }
            policies.append(policy)
            logging.info(f'Created ApplicationGroup and Policy for {group_name}')
    
    # Create final EPMP structure
    epmp_data = {
        'Policies': policies,
        'AppGroups': app_groups_list,
        'TrustSoftwareDistributors': [],
        'UserAccessTokens': [],
        'EndUserUIs': None
    }
    
    total_policies = len(policies)
    total_app_groups = len(app_groups_list)
    logging.info(f'Conversion completed with {total_policies} policies and {total_app_groups} application groups')
    return epmp_data

def convert_file(input_file, output_file, conversion_mode):
    try:
        logging.info(f'Starting conversion from {input_file} to {output_file}')
        logging.info(f'Conversion mode: {conversion_mode}')
        
        if not os.path.exists(input_file):
            logging.error(f'Input file not found: {input_file}')
            return False
        
        # Encoding detection
        encodings_to_try = ['utf-16-le', 'utf-16-be', 'utf-16', 'utf-8']
        vfp_content = None
        
        for encoding in encodings_to_try:
            try:
                with open(input_file, 'r', encoding=encoding) as f:
                    vfp_content = f.read()
                    logging.info(f'Successfully read input file with encoding: {encoding}')
                    break
            except UnicodeDecodeError:
                continue
        
        if vfp_content is None:
            logging.error('Could not read file with any of the attempted encodings')
            return False
        
        epmp_data = convert_vfp_to_epmp(vfp_content, conversion_mode)
        if epmp_data is None:
            return False
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(epmp_data, f, indent=2, ensure_ascii=False)
            logging.info(f'Successfully wrote output file: {output_file}')
        
        # İstatistikleri göster
        total_policies = len(epmp_data['Policies'])
        total_app_groups = len(epmp_data['AppGroups'])
        total_apps = sum(len(policy['Applications']) for policy in epmp_data['Policies'])
        total_apps += sum(len(group['Applications']) for group in epmp_data['AppGroups'])
        
        logging.info(f'Conversion statistics:')
        logging.info(f'  - Total policies: {total_policies}')
        logging.info(f'  - Total application groups: {total_app_groups}')
        logging.info(f'  - Total applications: {total_apps}')
        
        return True
    except Exception as e:
        logging.error(f'Error during conversion: {str(e)}', exc_info=True)
        return False

def validate_output(output_file):
    """EPMP dosyasının geçerliliğini kontrol et"""
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        required_keys = ['Policies', 'AppGroups', 'TrustSoftwareDistributors', 'UserAccessTokens']
        for key in required_keys:
            if key not in data:
                logging.error(f'Missing required key in output: {key}')
                return False
        
        logging.info('Output file validation passed')
        return True
    except Exception as e:
        logging.error(f'Output validation failed: {str(e)}')
        return False

def main():
    # Setup logging
    log_file = setup_logging()
    logging.info('Starting Enhanced VFP to EPMP converter')
    
    # Get input and output file names
    while True:
        input_file = input('Enter input VFP file path: ').strip('"')
        if os.path.exists(input_file):
            break
        print('File not found. Please enter a valid file path.')
    
    # Generate default output name if none provided
    default_output = os.path.splitext(input_file)[0] + '.epmp'
    output_file = input(f'Enter output EPMP file path [{default_output}]: ').strip('"')
    if not output_file:
        output_file = default_output
    
    # Get conversion mode from user
    conversion_mode = get_conversion_mode()
    
    # Perform conversion
    success = convert_file(input_file, output_file, conversion_mode)
    
    if success:
        # Validate the output
        if validate_output(output_file):
            print(f'\n✅ Conversion completed successfully!')
            print(f'📁 Log file: {log_file}')
            print(f'📄 Output file: {output_file}')
        else:
            print(f'\n⚠️  Conversion completed but output validation failed.')
            print(f'📁 Log file: {log_file}')
    else:
        print(f'\n❌ Conversion failed. Please check the log file: {log_file}')

if __name__ == '__main__':
    main()
