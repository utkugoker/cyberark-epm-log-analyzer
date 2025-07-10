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
    log_filename = f'logs/trusted_sources_converter_{timestamp}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_filename

def get_compare_as_value(compare_as_text):
    """CompareAs mapping"""
    compare_map = {
        'exact': 0,
        'contains': 1,
        'wildcard': 2,
        'regex': 3
    }
    return compare_map.get(compare_as_text.lower(), 0)

def get_epmp_policy_type(internal_type):
    """VFP internalType'ından EPMP PolicyType'ını belirle"""
    type_mapping = {
        '280': 29,  # Publisher-based → Signature policy
        '281': 29,  # Installed by Publisher → Signature policy  
        '220': 27,  # Location-based → Network policy
        '221': 27,  # Installed from Location → Network policy
        '242': 24,  # Software Distribution → Software distribution policy
        # '244': Skip - "Installed by Software Distribution" policies are merged, not converted separately
        '230': 30,  # Product name → Product-based policy
        '231': 30,  # Installed from Product → Product-based policy
        '285': 30   # Product/Service → Product-based policy
    }
    
    # internalType="244" için None döndür - bu policy'ler ayrı convert edilmez
    if internal_type == '244':
        return None
    
    return type_mapping.get(internal_type, 29)  # Default to signature policy

def get_epmp_action(vfp_action, policy_type):
    """VFP action'ından EPMP action'ını belirle"""
    # VFP action mapping:
    # 1 = Allow, 2 = Deny, 3 = Require justification, 4 = Elevate
    
    # Trusted sources için genellikle Allow kullanılır
    if vfp_action == 1:  # VFP Allow
        return 1  # EPMP Allow
    elif vfp_action == 2:  # VFP Deny
        return 2  # EPMP Deny
    elif vfp_action == 3:  # VFP Require justification
        return 3  # EPMP Require justification
    elif vfp_action == 4:  # VFP Elevate
        return 4  # EPMP Elevate
    else:
        # Default for trusted sources is Allow
        return 1

def create_publisher_policy(policy_info, app_group_info):
    """Publisher-based Trusted Source Policy oluştur (PolicyType 29)"""
    # Publisher bilgisini ApplicationGroup'tan al
    publisher_content = ""
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            publisher_elem = element.find('Publisher')
            if publisher_elem is not None and publisher_elem.text:
                publisher_content = publisher_elem.text.strip()
                break
        if publisher_content:
            break
    
    # FileOrigin'den de publisher alabilir
    if not publisher_content:
        for app in app_group_info.get('applications', []):
            for element in app.get('elements', []):
                file_origin = element.find('FileOrigin')
                if file_origin is not None:
                    package = file_origin.find('Package')
                    if package is not None:
                        package_publisher = package.find('Publisher')
                        if package_publisher is not None and package_publisher.text:
                            publisher_content = package_publisher.text.strip()
                            break
            if publisher_content:
                break

    # Action'ı belirle
    action = get_epmp_action(policy_info['action'], 29)
    
    policy = {
        'Id': str(uuid4()),  # YENİ UUID oluştur - VFP ID'sini kullanma
        'Name': f"Signature '{publisher_content}'" if publisher_content else policy_info['name'],
        'PolicyType': 29,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 280},  # YENİ UUID
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 281}   # YENİ UUID
        ],
        'Audit': False,
        'Publisher': {
            '@type': 'Publisher',
            'separator': ';',
            'signatureLevel': 2,
            'content': publisher_content,
            'compareAs': 0,
            'caseSensitive': True,
            'isEmpty': False
        },
        'ApplyPolicyOnInstalledApplications': True,
        'ApplyPolicyOnLocalHardDrivesOnly': False,
        'IsActive': True,
        'ReplaceUAC': action == 4,  # Sadece Elevate action'ında UAC replace
        'ReplaceUacAdmin': action == 4,
        'ShellExtension': False,
        'IsTargetedEXE': True,
        'IsTargetedDLL': True,
        'IsTargetedMSI': True,
        'IsTargetedMSU': True,
        'IsTargetedScript': True,
        'IsTargetedCOM': True,
        'IsTargetedActiveX': True,
        'UIReplaceUAC': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
        'UIReplaceUacAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
        'UIShellExtension': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'}
    }
    
    return policy

def create_network_policy(policy_info, app_group_info):
    """Network-based Trusted Source Policy oluştur (PolicyType 27)"""
    # Network location bilgisini ApplicationGroup'tan al
    network_location = ""
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            location_elem = element.find('Location')
            if location_elem is not None and location_elem.text:
                network_location = location_elem.text.strip()
                break
        if network_location:
            break
    
    # FileOrigin'den de location alabilir
    if not network_location:
        for app in app_group_info.get('applications', []):
            for element in app.get('elements', []):
                file_origin = element.find('FileOrigin')
                if file_origin is not None:
                    location_origin = file_origin.find('Location')
                    if location_origin is not None and location_origin.text:
                        network_location = location_origin.text.strip()
                        break
            if network_location:
                break

    # Action'ı belirle
    action = get_epmp_action(policy_info['action'], 27)

    policy = {
        'Id': str(uuid4()),
        'Name': policy_info['name'],
        'PolicyType': 27,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 220},
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 221}
        ],
        'Audit': False,
        'NetworkName': network_location,
        'ApplyPolicyOnInstalledApplications': True,
        'IsActive': True,
        'ReplaceUAC': action == 4,  # Sadece Elevate action'ında UAC replace
        'ReplaceUacAdmin': action == 4,
        'ShellExtension': False,
        'IsAnyNetworkShare': False,
        'IsNetworkShareSubfolders': True,
        'UIReplaceUAC': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
        'UIReplaceUacAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
        'UIShellExtension': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'}
    }
    
    return policy

def create_software_distribution_policy(policy_info, app_group_info, child_policy=None):
    """Software Distribution Trusted Source Policy oluştur (PolicyType 24)"""
    # Policy name'i orjinal olarak koru, sadece SoftwareName'i map et
    policy_name = policy_info['name']
    original_software_name = policy_info['name']
    
    # EPMP'nin 4 predefined distributor'una map et
    predefined_mapping = {
        # SCCM variations -> SCCM Software Distribution
        'sccm software distribution': 'SCCM Software Distribution',
        'system center configuration manager': 'SCCM Software Distribution',
        'microsoft sccm': 'SCCM Software Distribution',
        'sccm': 'SCCM Software Distribution',
        'configuration manager': 'SCCM Software Distribution',
        'system center': 'SCCM Software Distribution',
        'sms': 'SCCM Software Distribution',
        
        # McAfee ePO variations -> ePO Product Deployment
        'epo product deployment': 'ePO Product Deployment',
        'mcafee epo': 'ePO Product Deployment',
        'epo': 'ePO Product Deployment',
        'mcafee epolicy orchestrator': 'ePO Product Deployment',
        'epolicy orchestrator': 'ePO Product Deployment',
        
        # Intune variations -> Microsoft Intune
        'microsoft intune': 'Microsoft Intune',
        'intune': 'Microsoft Intune',
        'microsoft endpoint manager': 'Microsoft Intune',
        'endpoint manager': 'Microsoft Intune',
        
        # MDM variations -> Microsoft Mobile Device Management (Intune, etc.)
        'microsoft mobile device management (intune, etc.)': 'Microsoft Mobile Device Management (Intune, etc.)',
        'microsoft mobile device management': 'Microsoft Mobile Device Management (Intune, etc.)',
        'mobile device management': 'Microsoft Mobile Device Management (Intune, etc.)',
        'mdm': 'Microsoft Mobile Device Management (Intune, etc.)',
        'microsoft mdm': 'Microsoft Mobile Device Management (Intune, etc.)'
    }
    
    # Case-insensitive mapping
    software_name = original_software_name
    original_lower = original_software_name.lower()
    
    for key, predefined_value in predefined_mapping.items():
        if original_lower == key or original_lower.startswith(key):
            software_name = predefined_value
            logging.info(f'Mapped software distribution to predefined: "{original_software_name}" -> "{software_name}"')
            break
    
    # Eğer hiçbir predefined'a map edilmezse, orijinal ismi kullan ama log'la
    if software_name == original_software_name:
        logging.info(f'Using custom software distribution name: "{software_name}" (no predefined mapping found)')
    
    # Software Distribution politikaları için ana action her zaman Allow (1) olmalı
    action = 1  # Always Allow for software distribution trust
    
    # ChildAction (Installed Applications) için "Installed by" policy'nin action'ını kullan
    if child_policy:
        child_action = get_epmp_action(child_policy['action'], 24)
        logging.info(f'Using child policy action {child_policy["action"]} -> {child_action} for installed applications')
    else:
        # Eğer child policy yoksa, ana policy'nin action'ını kullan
        child_action = get_epmp_action(policy_info['action'], 24)
        logging.info(f'No child policy found, using main policy action {policy_info["action"]} -> {child_action} for installed applications')
    
    # ChildAction değerlerine göre ApplyPolicyOnInstalledApplications ayarla
    apply_on_installed = child_action != 0  # 0 = Off durumu
    
    # Base policy structure
    policy = {
        'Id': str(uuid4()),
        'Name': policy_name,  # Orijinal policy name'i koru
        'PolicyType': 24,
        'Action': action,  # Ana action her zaman Allow
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 242},
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 244}
        ],
        'SoftwareName': software_name,  # Predefined'a map edilmiş isim
        'ApplyPolicyOnInstalledApplications': apply_on_installed,
        'IsActive': True,
        'IsPredefined': software_name in ['SCCM Software Distribution', 'ePO Product Deployment', 'Microsoft Intune', 'Microsoft Mobile Device Management (Intune, etc.)'],  # Predefined ise True
        'Applications': []
    }
    
    # Child alanları sadece Off (0) değilse ekle
    if child_action != 0:
        policy.update({
            'ChildAction': child_action,
            'ChildAudit': False,
            'ChildMonitorInstallationOfNewApplications': False
        })
        
        # Child UAC replace settings - sadece ChildAction Elevate (4) ise ekle
        if child_action == 4:  # Elevate
            policy.update({
                'ChildReplaceUAC': True,
                'ChildReplaceUacAdmin': True,
                'ChildShellExtension': False,
                'ChildUIReplaceUAC': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
                'ChildUIReplaceUacAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
                'ChildUIShellExtension': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'}
            })
    
    return policy

def create_product_policy(policy_info, app_group_info):
    """Product-based Trusted Source Policy oluştur (PolicyType 30)"""
    # Product name bilgisini ApplicationGroup'tan al
    product_name = ""
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            # FileVerInfo'dan ProductName al
            for file_info in element.findall('FileVerInfo'):
                if file_info.get('name') == 'ProductName' and file_info.text:
                    product_name = file_info.text.strip()
                    break
            if product_name:
                break
        if product_name:
            break
    
    # Eğer bulunamazsa policy name'ini kullan
    if not product_name:
        product_name = policy_info['name']

    # Action'ı belirle
    action = get_epmp_action(policy_info['action'], 30)

    policy = {
        'Id': str(uuid4()),
        'Name': policy_info['name'],
        'PolicyType': 30,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': str(uuid4()), 'InternalId': 0, 'PolicyType': 285}
        ],
        'Audit': False,
        'ProductName': product_name,
        'ProductCompareAs': 0,
        'Publisher': {
            '@type': 'Publisher',
            'separator': ';',
            'signatureLevel': 2,
            'content': product_name,
            'compareAs': 0,
            'caseSensitive': True,
            'isEmpty': False
        },
        'IsActive': True,
        'ReplaceUAC': action == 4,  # Sadece Elevate action'ında UAC replace
        'ReplaceUacAdmin': action == 4,
        'ShellExtension': False,
        'IsTargetedEXE': True,
        'IsTargetedDLL': True,
        'IsTargetedMSI': True,
        'UIReplaceUAC': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
        'UIReplaceUacAdmin': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'},
        'UIShellExtension': {'Id': '00000000-0000-0000-0000-000000000000', 'AllowedDialogType': 'ElevateOnDemand'}
    }
    
    return policy

def parse_application_groups(root):
    """ApplicationGroups'ı parse et"""
    app_groups = {}
    
    app_groups_element = root.find('.//ApplicationGroups')
    if app_groups_element is not None:
        for app_group in app_groups_element.findall('ApplicationGroup'):
            group_id = app_group.get('id')
            group_name = app_group.get('name', '')
            group_description = app_group.get('description', '')
            
            # Tüm application element'lerini topla
            applications = []
            for element_type in ['Executable', 'Dll', 'MSI', 'MSU', 'ActiveXInstall', 'COM', 'Script']:
                elements = app_group.findall(element_type)
                if elements:
                    applications.append({
                        'type': element_type,
                        'elements': elements
                    })
            
            app_groups[group_id] = {
                'name': group_name,
                'description': group_description,
                'applications': applications
            }
    
    return app_groups

def parse_policies(root):
    """GpoPolicies ve PolicyDescriptions'ı parse et"""
    policies = {}
    
    # GpoPolicies'ı parse et
    gpo_policies = root.find('.//GpoPolicies')
    if gpo_policies is not None:
        for policy in gpo_policies.findall('Policy'):
            gpid = policy.get('gpid')
            name = policy.get('name', '')
            action = int(policy.get('action', '1'))
            internal_type = policy.get('internalType', '280')
            
            # Target ApplicationGroup'ları al
            target_app_groups = []
            targets = policy.find('Targets')
            if targets is not None:
                for app_group in targets.findall('ApplicationGroup'):
                    target_app_groups.append(app_group.get('id'))
            
            policies[gpid] = {
                'name': name,
                'action': action,
                'internal_type': internal_type,
                'target_app_groups': target_app_groups
            }
    
    # PolicyDescriptions'ı parse et
    policy_descriptions = root.find('.//PolicyDescriptions')
    if policy_descriptions is not None:
        for policy in policy_descriptions.findall('Policy'):
            gpid = policy.get('gpid')
            if gpid in policies:
                description_elem = policy.find('Description')
                description = description_elem.text if description_elem is not None and description_elem.text else ''
                
                all_computers_elem = policy.find('AllComputers')
                all_computers = all_computers_elem.text.lower() == 'true' if all_computers_elem is not None else True
                
                policies[gpid]['description'] = description
                policies[gpid]['all_computers'] = all_computers
    
    return policies

def convert_vfp_trusted_sources_to_epmp(vfp_content):
    """VFP Trusted Sources'ı EPMP formatına çevir"""
    root = ET.fromstring(vfp_content)
    logging.info('Successfully parsed VFP XML content')
    
    # Parse policies and application groups
    policies = parse_policies(root)
    app_groups = parse_application_groups(root)
    
    logging.info(f'Found {len(policies)} policies and {len(app_groups)} application groups')
    
    # Convert each policy to EPMP format
    epmp_policies = []
    
    for gpid, policy_info in policies.items():
        logging.info(f'Processing policy: {policy_info["name"]} (Type: {policy_info["internal_type"]}, Action: {policy_info["action"]})')
        
        # İlgili ApplicationGroup bilgilerini topla
        app_group_info = {'applications': []}
        for app_group_id in policy_info['target_app_groups']:
            if app_group_id in app_groups:
                app_group_info = app_groups[app_group_id]
                break
        
        # Policy type'ına göre uygun EPMP policy oluştur
        epmp_policy_type = get_epmp_policy_type(policy_info['internal_type'])
        
        if epmp_policy_type == 29:  # Publisher-based
            epmp_policy = create_publisher_policy(policy_info, app_group_info)
            epmp_policies.append(epmp_policy)
            
            # Action mapping'i log'a ekle
            action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
            vfp_action_name = action_names.get(policy_info['action'], f'Unknown({policy_info["action"]})')
            epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
            logging.info(f'Created EPMP policy: {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: {vfp_action_name} → {epmp_action_name})')
        elif epmp_policy_type == 27:  # Network-based
            epmp_policy = create_network_policy(policy_info, app_group_info)
            epmp_policies.append(epmp_policy)
            
            # Action mapping'i log'a ekle
            action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
            vfp_action_name = action_names.get(policy_info['action'], f'Unknown({policy_info["action"]})')
            epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
            logging.info(f'Created EPMP policy: {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: {vfp_action_name} → {epmp_action_name})')
        elif epmp_policy_type == 24:  # Software distribution
            epmp_policy = create_software_distribution_policy(policy_info, app_group_info)
        elif epmp_policy_type == 30:  # Product-based
            epmp_policy = create_product_policy(policy_info, app_group_info)
        else:
            logging.warning(f'Unknown policy type {epmp_policy_type} for policy {policy_info["name"]}')
            continue
        
        epmp_policies.append(epmp_policy)
        
        # Action mapping'i log'a ekle
        action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
        vfp_action_name = action_names.get(policy_info['action'], f'Unknown({policy_info["action"]})')
        epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
        
        # Software Distribution için özel logging
        if epmp_policy_type == 24:
            child_action_name = action_names.get(epmp_policy['ChildAction'], f'Unknown({epmp_policy["ChildAction"]})')
            logging.info(f'Created Software Distribution policy: {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: Allow, Installed Apps: {child_action_name})')
        else:
            logging.info(f'Created EPMP policy: {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: {vfp_action_name} → {epmp_action_name})')
    
    # Create EPMP structure
    epmp_data = {
        'Policies': epmp_policies,
        'AppGroups': [],  # Trusted Sources için AppGroup oluşturmuyoruz
        'TrustSoftwareDistributors': [],
        'UserAccessTokens': [],
        'EndUserUIs': None
    }
    
    # İstatistikleri hesapla
    policy_type_counts = {}
    action_counts = {}
    for policy in epmp_policies:
        policy_type = policy['PolicyType']
        policy_type_counts[policy_type] = policy_type_counts.get(policy_type, 0) + 1
        
        action = policy['Action']
        action_counts[action] = action_counts.get(action, 0) + 1
    
    logging.info(f'Conversion completed!')
    logging.info(f'Total trusted source policies created: {len(epmp_policies)}')
    
    # Policy type statistics
    for policy_type, count in policy_type_counts.items():
        type_name = {29: 'Publisher-based', 27: 'Network-based', 24: 'Software Distribution', 30: 'Product-based'}.get(policy_type, f'Type {policy_type}')
        logging.info(f'  - {type_name}: {count}')
    
    # Action statistics
    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
    logging.info('Action distribution:')
    for action, count in action_counts.items():
        action_name = action_names.get(action, f'Action {action}')
        logging.info(f'  - {action_name}: {count}')
    
    # Software Distribution Child Action statistics
    child_action_counts = {}
    for policy in epmp_policies:
        if policy['PolicyType'] == 24:  # Software Distribution
            child_action = policy.get('ChildAction')
            child_action_counts[child_action] = child_action_counts.get(child_action, 0) + 1
    
    if child_action_counts:
        logging.info('Software Distribution Installed Applications action distribution:')
        for action, count in child_action_counts.items():
            action_name = action_names.get(action, f'Action {action}')
            logging.info(f'  - {action_name}: {count}')
    
    return epmp_data

def convert_file(input_file, output_file):
    """VFP dosyasını EPMP formatına çevir"""
    try:
        logging.info(f'Starting trusted sources conversion from {input_file} to {output_file}')
        
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
        
        epmp_data = convert_vfp_trusted_sources_to_epmp(vfp_content)
        if epmp_data is None:
            return False
        
        # Ana EPMP dosyasını yaz
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(epmp_data, f, indent=2, ensure_ascii=False)
            logging.info(f'Successfully wrote main output file: {output_file}')
        
        # Source tipine göre ayrı dosyalar oluştur
        create_separate_source_files(epmp_data, output_file)
        
        return True
    except Exception as e:
        logging.error(f'Error during conversion: {str(e)}', exc_info=True)
        return False

def create_separate_source_files(epmp_data, base_output_file):
    """Source tipine göre ayrı EPMP dosyaları oluştur"""
    try:
        # Base filename'i al
        base_path = os.path.splitext(base_output_file)[0]
        
        # Policy tipine göre grupla
        policy_groups = {
            'publisher': [],      # PolicyType 29 - Publisher-based
            'network': [],        # PolicyType 27 - Network-based  
            'software_dist': [],  # PolicyType 24 - Software Distribution
            'product': []         # PolicyType 30 - Product-based
        }
        
        # Politikaları grupla
        for policy in epmp_data['Policies']:
            policy_type = policy.get('PolicyType')
            if policy_type == 29:
                policy_groups['publisher'].append(policy)
            elif policy_type == 27:
                policy_groups['network'].append(policy)
            elif policy_type == 24:
                policy_groups['software_dist'].append(policy)
            elif policy_type == 30:
                policy_groups['product'].append(policy)
        
        # Her grup için ayrı dosya oluştur
        type_names = {
            'publisher': 'Publisher-based',
            'network': 'Network-based',
            'software_dist': 'Software Distribution',
            'product': 'Product-based'
        }
        
        for group_key, policies in policy_groups.items():
            if policies:  # Sadece policy'si olan gruplar için dosya oluştur
                separate_data = {
                    'Policies': policies,
                    'AppGroups': [],
                    'TrustSoftwareDistributors': [],
                    'UserAccessTokens': [],
                    'EndUserUIs': None
                }
                
                output_filename = f"{base_path}_{group_key}.epmp"
                with open(output_filename, 'w', encoding='utf-8') as f:
                    json.dump(separate_data, f, indent=2, ensure_ascii=False)
                
                logging.info(f'Created {type_names[group_key]} file: {output_filename} ({len(policies)} policies)')
        
        logging.info('Successfully created separate source type files')
        
    except Exception as e:
        logging.error(f'Error creating separate source files: {str(e)}', exc_info=True)

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
        
        # Policy type'larını kontrol et
        valid_policy_types = [24, 27, 29, 30]
        for policy in data['Policies']:
            if policy.get('PolicyType') not in valid_policy_types:
                logging.warning(f'Unexpected policy type: {policy.get("PolicyType")} for policy {policy.get("Name")}')
        
        # Action distribution'ını kontrol et
        action_counts = {}
        for policy in data['Policies']:
            action = policy.get('Action')
            action_counts[action] = action_counts.get(action, 0) + 1
        
        logging.info('Output file validation passed')
        action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
        for action, count in action_counts.items():
            action_name = action_names.get(action, f'Action {action}')
            logging.info(f'Final action distribution - {action_name}: {count}')
        
        return True
    except Exception as e:
        logging.error(f'Output validation failed: {str(e)}')
        return False

def main():
    """Ana fonksiyon"""
    # Setup logging
    log_file = setup_logging()
    logging.info('Starting VFP Trusted Sources to EPMP converter')
    
    # Get input and output file names
    while True:
        input_file = input('Enter input VFP file path: ').strip('"')
        if os.path.exists(input_file):
            break
        print('File not found. Please enter a valid file path.')
    
    # Generate default output name if none provided
    default_output = os.path.splitext(input_file)[0] + '_trusted_sources.epmp'
    output_file = input(f'Enter output EPMP file path [{default_output}]: ').strip('"')
    if not output_file:
        output_file = default_output
    
    # Perform conversion
    success = convert_file(input_file, output_file)
    
    if success:
        # Validate the output
        if validate_output(output_file):
            print(f'\n✅ Trusted Sources conversion completed successfully!')
            print(f'📁 Log file: {log_file}')
            print(f'📄 Output file: {output_file}')
            print(f'\nThe converter has created EPMP Trusted Source policies:')
            print(f'  - Publisher-based policies (PolicyType 29)')
            print(f'  - Network-based policies (PolicyType 27)')
            print(f'  - Software Distribution policies (PolicyType 24)')
            print(f'  - Product-based policies (PolicyType 30)')
            print(f'\nAction types are now correctly mapped based on original VFP policy actions.')
        else:
            print(f'\n⚠️  Conversion completed but output validation failed.')
            print(f'📁 Log file: {log_file}')
    else:
        print(f'\n❌ Conversion failed. Please check the log file: {log_file}')

if __name__ == '__main__':
    main()
