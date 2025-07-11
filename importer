#!/usr/bin/env python3
"""
VFP to EPMP Trusted Sources Converter
Converts VFP (Viewfinity Policy) trusted source policies to EPMP format
"""

import xml.etree.ElementTree as ET
import json
import os
import sys
import logging
from uuid import uuid4
from datetime import datetime

def setup_logging():
    """Setup logging configuration"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f'logs/trusted_sources_converter_{timestamp}.log'
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_filename

def parse_policies(root):
    """Parse VFP policies from XML"""
    policies = {}
    
    # GpoPolicies altındaki Policy'leri bul
    gpo_policies = root.find('.//GpoPolicies')
    if gpo_policies is not None:
        logging.info(f'Found GpoPolicies element')
        policy_elements = gpo_policies.findall('Policy')
        logging.info(f'Found {len(policy_elements)} Policy elements in GpoPolicies')
    else:
        logging.error('GpoPolicies element not found!')
        return policies
    
    for policy in gpo_policies.findall('Policy'):
        gpid = policy.get('gpid', '').strip('{}')
        if not gpid:
            continue
        
        # Attribute'ları doğru şekilde al
        name = policy.get('name', '')
        action_str = policy.get('action', '1')
        internal_type = policy.get('internalType', '')
        
        # Action'ı integer'a çevir
        try:
            action = int(action_str)
        except (ValueError, TypeError):
            action = 1
        
        policy_info = {
            'gpid': gpid,
            'name': name,
            'action': action,
            'description': policy.get('description', ''),
            'internal_type': internal_type,
            'target_app_groups': []
        }
        
        # Parse target application groups
        targets = policy.find('Targets')
        if targets is not None:
            for app_group in targets.findall('ApplicationGroup'):
                app_group_id = app_group.get('id', '').strip('{}')
                if app_group_id:
                    policy_info['target_app_groups'].append(app_group_id)
        
        if policy_info['name'] or policy_info['internal_type']:
            policies[gpid] = policy_info
        
    logging.info(f'Successfully parsed {len(policies)} policies')
    return policies

def parse_application_groups(root):
    """Parse VFP application groups from XML"""
    app_groups = {}
    
    # ApplicationGroups altındaki ApplicationGroup'ları bul
    app_groups_element = root.find('.//ApplicationGroups')
    if app_groups_element is not None:
        app_group_elements = app_groups_element.findall('ApplicationGroup')
        logging.info(f'Found {len(app_group_elements)} ApplicationGroup elements')
    else:
        logging.error('ApplicationGroups element not found!')
        return app_groups
    
    for app_group in app_groups_element.findall('ApplicationGroup'):
        group_id = app_group.get('id', '').strip('{}')
        if not group_id:
            continue
            
        group_info = {
            'id': group_id,
            'name': app_group.get('name', ''),
            'description': app_group.get('description', ''),
            'applications': []
        }
        
        # Parse applications in the group
        applications = []
        for executable in app_group.findall('.//Executable'):
            applications.append({'type': 'Executable', 'elements': [executable]})
        for msi in app_group.findall('.//MSI'):
            applications.append({'type': 'MSI', 'elements': [msi]})
        for script in app_group.findall('.//Script'):
            applications.append({'type': 'Script', 'elements': [script]})
        for dll in app_group.findall('.//Dll'):
            applications.append({'type': 'Dll', 'elements': [dll]})
        for com in app_group.findall('.//COM'):
            applications.append({'type': 'COM', 'elements': [com]})
        for activex in app_group.findall('.//ActiveXInstall'):
            applications.append({'type': 'ActiveXInstall', 'elements': [activex]})
        for msu in app_group.findall('.//MSU'):
            applications.append({'type': 'MSU', 'elements': [msu]})
            
        group_info['applications'] = applications
        app_groups[group_id] = group_info
        
    logging.info(f'Successfully parsed {len(app_groups)} application groups')
    return app_groups

def get_epmp_action(vfp_action, policy_type):
    """VFP action'ından EPMP action'ına çevir"""
    return vfp_action  # Direct mapping

def get_epmp_policy_type(internal_type):
    """VFP internalType'ından EPMP PolicyType'ını belirle"""
    type_mapping = {
        '280': 29,  # Publisher-based → Signature policy
        '281': None,  # Installed by Publisher → Skip (merge with 280)
        '220': 27,  # Location-based → Network policy
        '221': 27,  # Installed from Location → Network policy
        '242': 24,  # Software Distribution → Software distribution policy
        '244': None,  # Installed by Software Distribution → Skip
        '230': 30,  # Product name → Product-based policy
        '231': None,  # Installed from Product → Skip
        '285': 30   # Product/Service → Product-based policy
    }
    
    return type_mapping.get(internal_type, 29)

def analyze_source_application_types(app_group_info):
    """281 policy'sinin ApplicationGroup'undaki dosya tiplerini analiz et"""
    targeted_types = {
        'IsTargetedEXE': False,
        'IsTargetedDLL': False,
        'IsTargetedMSI': False,
        'IsTargetedMSU': False,
        'IsTargetedScript': False,
        'IsTargetedCOM': False,
        'IsTargetedActiveX': False
    }
    
    for app in app_group_info.get('applications', []):
        app_type = app.get('type', '')
        
        if app_type == 'Executable':
            targeted_types['IsTargetedEXE'] = True
        elif app_type == 'Dll':
            targeted_types['IsTargetedDLL'] = True
        elif app_type == 'MSI':
            targeted_types['IsTargetedMSI'] = True
        elif app_type == 'MSU':
            targeted_types['IsTargetedMSU'] = True
        elif app_type == 'Script':
            targeted_types['IsTargetedScript'] = True
        elif app_type == 'COM':
            targeted_types['IsTargetedCOM'] = True
        elif app_type == 'ActiveXInstall':
            targeted_types['IsTargetedActiveX'] = True
    
    found_types = [key for key, value in targeted_types.items() if value]
    if found_types:
        logging.info(f'Found application types: {", ".join(found_types)}')
    else:
        logging.warning('No application types found, defaulting to EXE')
        targeted_types['IsTargetedEXE'] = True
    
    return targeted_types

def analyze_product_source_application_types(app_group_info):
    """231 policy'sinin ApplicationGroup'undaki dosya tiplerini analiz et (Product için)"""
    targeted_types = {
        'IsTargetedEXE': False,
        'IsTargetedDLL': False,
        'IsTargetedMSI': False
        # Product policy'lerde sadece EXE, DLL, MSI var
    }
    
    for app in app_group_info.get('applications', []):
        app_type = app.get('type', '')
        
        if app_type == 'Executable':
            targeted_types['IsTargetedEXE'] = True
        elif app_type == 'Dll':
            targeted_types['IsTargetedDLL'] = True
        elif app_type == 'MSI':
            targeted_types['IsTargetedMSI'] = True
    
    found_types = [key for key, value in targeted_types.items() if value]
    if found_types:
        logging.info(f'Found product application types: {", ".join(found_types)}')
    else:
        logging.warning('No product application types found, defaulting to EXE')
        targeted_types['IsTargetedEXE'] = True
    
    return targeted_types

def get_publisher_policy_mapping(policies):
    """280 ve 281 policy'lerini eşleştir ve grupla"""
    publisher_mapping = {}
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '280':  # Ana Publisher policy
            publisher_name = policy_info['name']
            if publisher_name not in publisher_mapping:
                publisher_mapping[publisher_name] = {}
            publisher_mapping[publisher_name]['main'] = policy_info
            publisher_mapping[publisher_name]['main_gpid'] = gpid
            
        elif policy_info['internal_type'] == '281':  # Installed by Publisher
            policy_name = policy_info['name']
            if policy_name.startswith('Installed by: '):
                publisher_name = policy_name[13:]  # "Installed by: " prefix'ini kaldır
                if publisher_name not in publisher_mapping:
                    publisher_mapping[publisher_name] = {}
                publisher_mapping[publisher_name]['source_app'] = policy_info
                publisher_mapping[publisher_name]['source_app_gpid'] = gpid
    
    logging.info(f'Publisher mapping created: {len(publisher_mapping)} groups')
    return publisher_mapping

def get_product_policy_mapping(policies):
    """230, 231 ve 285 policy'lerini eşleştir ve grupla"""
    product_mapping = {}
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '230':  # Ana Product policy
            product_name = policy_info['name']
            if product_name not in product_mapping:
                product_mapping[product_name] = {}
            product_mapping[product_name]['main'] = policy_info
            product_mapping[product_name]['main_gpid'] = gpid
            
        elif policy_info['internal_type'] == '231':  # Installed from Product
            policy_name = policy_info['name']
            if policy_name.startswith('Installed from: '):
                product_name = policy_name[15:]  # "Installed from: " prefix'ini kaldır
                if product_name not in product_mapping:
                    product_mapping[product_name] = {}
                product_mapping[product_name]['source_app'] = policy_info
                product_mapping[product_name]['source_app_gpid'] = gpid
                
        elif policy_info['internal_type'] == '285':  # Product/Service policy
            product_name = policy_info['name']
            if product_name not in product_mapping:
                product_mapping[product_name] = {}
            product_mapping[product_name]['main'] = policy_info
            product_mapping[product_name]['main_gpid'] = gpid
    
    logging.info(f'Product mapping created: {len(product_mapping)} groups')
    return product_mapping

def create_publisher_policy_with_source_types(main_policy_info, source_app_policy_info, main_app_group_info, source_app_group_info):
    """Publisher policy'sini Source Application Types analizi ile oluştur"""
    
    # Publisher bilgisini al
    publisher_content = ""
    compare_as = 0
    case_sensitive = True
    
    for app in main_app_group_info.get('applications', []):
        for element in app.get('elements', []):
            publisher_elem = element.find('Publisher')
            if publisher_elem is not None and publisher_elem.text:
                publisher_content = publisher_elem.text.strip()
                
                compare_as_attr = publisher_elem.get('compareAs', 'exact')
                if compare_as_attr == 'exact':
                    compare_as = 0
                elif compare_as_attr == 'startsWith':
                    compare_as = 1
                elif compare_as_attr == 'endsWith':
                    compare_as = 2
                elif compare_as_attr == 'contains':
                    compare_as = 3
                
                case_sensitive_attr = publisher_elem.get('caseSensitive', 'True')
                case_sensitive = case_sensitive_attr.lower() == 'true'
                break
        if publisher_content:
            break
    
    # FileOrigin'den de publisher alabilir
    if not publisher_content:
        for app in main_app_group_info.get('applications', []):
            for element in app.get('elements', []):
                file_origin = element.find('FileOrigin')
                if file_origin is not None:
                    package = file_origin.find('Package')
                    if package is not None:
                        package_publisher = package.find('Publisher')
                        if package_publisher is not None and package_publisher.text:
                            publisher_content = package_publisher.text.strip()
                            
                            compare_as_attr = package_publisher.get('compareAs', 'exact')
                            if compare_as_attr == 'exact':
                                compare_as = 0
                            elif compare_as_attr == 'startsWith':
                                compare_as = 1
                            elif compare_as_attr == 'endsWith':
                                compare_as = 2
                            elif compare_as_attr == 'contains':
                                compare_as = 3
                            
                            case_sensitive_attr = package_publisher.get('caseSensitive', 'True')
                            case_sensitive = case_sensitive_attr.lower() == 'true'
                            break
            if publisher_content:
                break

    if not publisher_content:
        publisher_content = main_policy_info['name']
        logging.warning(f'No publisher found, using policy name: {publisher_content}')

    # Source Application Types'ı analiz et
    if source_app_policy_info and source_app_group_info:
        targeted_types = analyze_source_application_types(source_app_group_info)
        logging.info(f'Source Application Types for "{publisher_content}": {targeted_types}')
    else:
        targeted_types = {
            'IsTargetedEXE': True,
            'IsTargetedDLL': True,
            'IsTargetedMSI': True,
            'IsTargetedMSU': True,
            'IsTargetedScript': True,
            'IsTargetedCOM': True,
            'IsTargetedActiveX': True
        }
        logging.info(f'No source app policy found for "{publisher_content}", using defaults')

    action = get_epmp_action(main_policy_info['action'], 29)
    
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    policy = {
        'Id': main_policy_id,
        'Name': f"Signature '{publisher_content}'" if publisher_content else main_policy_info['name'],
        'PolicyType': 29,
        'Action': action,
        'Description': main_policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 280},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 281}
        ],
        'Audit': False,
        'Publisher': {
            '@type': 'Publisher',
            'separator': ';',
            'signatureLevel': 2,
            'content': publisher_content,
            'compareAs': compare_as,
            'caseSensitive': case_sensitive,
            'isEmpty': not bool(publisher_content)
        },
        'ApplyPolicyOnInstalledApplications': True,
        'ApplyPolicyOnLocalHardDrivesOnly': False,
        'IsActive': True
    }
    
    policy.update(targeted_types)
    
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    return policy

def create_product_policy_with_source_types(main_policy_info, source_app_policy_info, main_app_group_info, source_app_group_info):
    """Product policy'sini Source Application Types analizi ile oluştur"""
    
    # Product name bilgisini al
    product_name = ""
    
    for app in main_app_group_info.get('applications', []):
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
    
    # FileOrigin'den de ProductName alabilir
    if not product_name:
        for app in main_app_group_info.get('applications', []):
            for element in app.get('elements', []):
                file_origin = element.find('FileOrigin')
                if file_origin is not None:
                    package = file_origin.find('Package')
                    if package is not None:
                        for file_info in package.findall('FileVerInfo'):
                            if file_info.get('name') == 'ProductName' and file_info.text:
                                product_name = file_info.text.strip()
                                break
                if product_name:
                    break
            if product_name:
                break
    
    if not product_name:
        product_name = main_policy_info['name']
        logging.warning(f'No ProductName found, using policy name: {product_name}')

    # Source Application Types'ı analiz et
    if source_app_policy_info and source_app_group_info:
        targeted_types = analyze_product_source_application_types(source_app_group_info)
        logging.info(f'Product Source Application Types for "{product_name}": {targeted_types}')
    else:
        targeted_types = {
            'IsTargetedEXE': True,
            'IsTargetedDLL': True,
            'IsTargetedMSI': True
        }
        logging.info(f'No source app policy found for product "{product_name}", using defaults')

    action = get_epmp_action(main_policy_info['action'], 30)
    
    main_policy_id = str(uuid4())
    linked_policy_id = str(uuid4())
    
    policy = {
        'Id': main_policy_id,
        'Name': main_policy_info['name'],
        'PolicyType': 30,
        'Action': action,
        'Description': main_policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_id, 'InternalId': 0, 'PolicyType': 285}
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
        'IsActive': True
    }
    
    policy.update(targeted_types)
    
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    return policy

def create_network_policy(policy_info, app_group_info):
    """Network-based Trusted Source Policy oluştur"""
    network_location = ""
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            location_elem = element.find('Location')
            if location_elem is not None and location_elem.text:
                network_location = location_elem.text.strip()
                break
        if network_location:
            break
    
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

    action = get_epmp_action(policy_info['action'], 27)
    
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())

    policy = {
        'Id': main_policy_id,
        'Name': policy_info['name'],
        'PolicyType': 27,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 220},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 221}
        ],
        'Audit': False,
        'NetworkName': network_location,
        'ApplyPolicyOnInstalledApplications': True,
        'IsActive': True,
        'IsAnyNetworkShare': False,
        'IsNetworkShareSubfolders': True
    }
    
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    return policy

def create_software_distribution_policy(policy_info, app_group_info, child_policy=None):
    """Software Distribution Trusted Source Policy oluştur"""
    policy_name = policy_info['name']
    original_software_name = policy_info['name']
    
    predefined_mapping = {
        'sccm software distribution': 'SCCM Software Distribution',
        'system center configuration manager': 'SCCM Software Distribution',
        'microsoft sccm': 'SCCM Software Distribution',
        'sccm': 'SCCM Software Distribution',
        'configuration manager': 'SCCM Software Distribution',
        'system center': 'SCCM Software Distribution',
        'sms': 'SCCM Software Distribution',
        'epo product deployment': 'ePO Product Deployment',
        'mcafee epo': 'ePO Product Deployment',
        'epo': 'ePO Product Deployment',
        'mcafee epolicy orchestrator': 'ePO Product Deployment',
        'epolicy orchestrator': 'ePO Product Deployment',
        'microsoft intune': 'Microsoft Intune',
        'intune': 'Microsoft Intune',
        'microsoft endpoint manager': 'Microsoft Intune',
        'endpoint manager': 'Microsoft Intune',
        'microsoft mobile device management (intune, etc.)': 'Microsoft Mobile Device Management (Intune, etc.)',
        'microsoft mobile device management': 'Microsoft Mobile Device Management (Intune, etc.)',
        'mobile device management': 'Microsoft Mobile Device Management (Intune, etc.)',
        'mdm': 'Microsoft Mobile Device Management (Intune, etc.)',
        'microsoft mdm': 'Microsoft Mobile Device Management (Intune, etc.)'
    }
    
    software_name = original_software_name
    original_lower = original_software_name.lower()
    
    for key, predefined_value in predefined_mapping.items():
        if original_lower == key or original_lower.startswith(key):
            software_name = predefined_value
            logging.info(f'Mapped software distribution: "{original_software_name}" -> "{software_name}"')
            break
    
    if software_name == original_software_name:
        logging.info(f'Using custom software distribution name: "{software_name}"')
    
    action = 1  # Always Allow for software distribution trust
    
    if child_policy:
        child_action = get_epmp_action(child_policy['action'], 24)
    else:
        child_action = get_epmp_action(policy_info['action'], 24)
    
    apply_on_installed = child_action != 0
    
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    policy = {
        'Id': main_policy_id,
        'Name': policy_name,
        'PolicyType': 24,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 242},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 244}
        ],
        'SoftwareName': software_name,
        'ApplyPolicyOnInstalledApplications': apply_on_installed,
        'IsActive': True,
        'IsPredefined': software_name in ['SCCM Software Distribution', 'ePO Product Deployment', 'Microsoft Intune', 'Microsoft Mobile Device Management (Intune, etc.)'],
        'Applications': []
    }
    
    if child_action != 0:
        policy.update({
            'ChildAction': child_action,
            'ChildAudit': False,
            'ChildMonitorInstallationOfNewApplications': False
        })
        
        if child_action == 4:  # Elevate
            policy.update({
                'ChildReplaceUAC': True,
                'ChildReplaceUacAdmin': True,
                'ChildShellExtension': False
            })
    
    return policy

def convert_vfp_trusted_sources_to_epmp(vfp_content):
    """VFP Trusted Sources'ı EPMP formatına çevir"""
    root = ET.fromstring(vfp_content)
    logging.info('Successfully parsed VFP XML content')
    
    policies = parse_policies(root)
    app_groups = parse_application_groups(root)
    
    logging.info(f'Found {len(policies)} policies and {len(app_groups)} application groups')
    
    if len(policies) == 0:
        logging.error('NO POLICIES FOUND!')
        return None
        
    if len(app_groups) == 0:
        logging.error('NO APPLICATION GROUPS FOUND!')
        return None
    
    # Software Distribution policy'lerini gruplayalım
    software_dist_groups = {}
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] in ['242', '244']:
            name = policy_info['name']
            if policy_info['internal_type'] == '244' and name.startswith('Installed by: '):
                software_name = name[14:]
            elif policy_info['internal_type'] == '242':
                software_name = name
            else:
                software_name = name
            
            if software_name not in software_dist_groups:
                software_dist_groups[software_name] = {}
            
            software_dist_groups[software_name][policy_info['internal_type']] = policy_info
    
    # Publisher ve Product mapping'lerini al
    publisher_mapping = get_publisher_policy_mapping(policies)
    product_mapping = get_product_policy_mapping(policies)
    
    epmp_policies = []
    processed_software_dist = set()
    processed_network = set()
    processed_publisher = set()
    processed_product = set()
    skipped_policies = []
    
    used_policy_ids = set()
    
    def add_policy_with_id_check(policy):
        policy_id = policy['Id']
        if policy_id in used_policy_ids:
            logging.error(f'DUPLICATE ID DETECTED: {policy_id}')
            new_id = str(uuid4())
            policy['Id'] = new_id
            policy_id = new_id
        
        used_policy_ids.add(policy_id)
        epmp_policies.append(policy)
        return True
    
    # Publisher policy'lerini işle
    logging.info('=== PROCESSING PUBLISHER POLICIES ===')
    for publisher_name, policy_data in publisher_mapping.items():
        if publisher_name not in processed_publisher:
            main_policy = policy_data.get('main')
            source_app_policy = policy_data.get('source_app')
            
            if main_policy:
                main_app_group_info = {'applications': []}
                for app_group_id in main_policy['target_app_groups']:
                    if app_group_id in app_groups:
                        main_app_group_info = app_groups[app_group_id]
                        break
                
                source_app_group_info = {'applications': []}
                if source_app_policy:
                    for app_group_id in source_app_policy['target_app_groups']:
                        if app_group_id in app_groups:
                            source_app_group_info = app_groups[app_group_id]
                            break
                
                try:
                    epmp_policy = create_publisher_policy_with_source_types(
                        main_policy, source_app_policy, 
                        main_app_group_info, source_app_group_info
                    )
                    
                    add_policy_with_id_check(epmp_policy)
                    processed_publisher.add(publisher_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(main_policy['action'], f'Unknown({main_policy["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    
                    if source_app_policy:
                        logging.info(f'✅ Created Publisher policy with Source App Types: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                    else:
                        logging.info(f'✅ Created Publisher policy: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                        
                except Exception as e:
                    logging.error(f'❌ Error creating publisher policy for "{publisher_name}": {str(e)}', exc_info=True)
            
            elif source_app_policy:
                logging.warning(f'Found orphaned Source App policy: {publisher_name}')
                processed_publisher.add(publisher_name)
    
    # Product policy'lerini işle
    logging.info('=== PROCESSING PRODUCT POLICIES ===')
    for product_name, policy_data in product_mapping.items():
        if product_name not in processed_product:
            main_policy = policy_data.get('main')
            source_app_policy = policy_data.get('source_app')
            
            if main_policy:
                main_app_group_info = {'applications': []}
                for app_group_id in main_policy['target_app_groups']:
                    if app_group_id in app_groups:
                        main_app_group_info = app_groups[app_group_id]
                        break
                
                source_app_group_info = {'applications': []}
                if source_app_policy:
                    for app_group_id in source_app_policy['target_app_groups']:
                        if app_group_id in app_groups:
                            source_app_group_info = app_groups[app_group_id]
                            break
                
                try:
                    epmp_policy = create_product_policy_with_source_types(
                        main_policy, source_app_policy, 
                        main_app_group_info, source_app_group_info
                    )
                    
                    add_policy_with_id_check(epmp_policy)
                    processed_product.add(product_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(main_policy['action'], f'Unknown({main_policy["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    
                    if source_app_policy:
                        logging.info(f'✅ Created Product policy with Source App Types: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                    else:
                        logging.info(f'✅ Created Product policy: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                        
                except Exception as e:
                    logging.error(f'❌ Error creating product policy for "{product_name}": {str(e)}', exc_info=True)
            
            elif source_app_policy:
                logging.warning(f'Found orphaned Product Source App policy: {product_name}')
                processed_product.add(product_name)
    
    # Skip edilecek policy'leri listele
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] in ['281', '231', '244']:
            skipped_policies.append(policy_info['name'])
    
    # Diğer policy'leri işle
    logging.info('=== PROCESSING OTHER POLICIES ===')
    for gpid, policy_info in policies.items():
        # Skip zaten işlenmiş policy'leri
        if policy_info['internal_type'] in ['244', '231', '281', '280', '230', '285']:
            continue
        
        app_group_info = {'applications': []}
        for app_group_id in policy_info['target_app_groups']:
            if app_group_id in app_groups:
                app_group_info = app_groups[app_group_id]
                break
        
        epmp_policy_type = get_epmp_policy_type(policy_info['internal_type'])
        
        try:
            if epmp_policy_type == 27:  # Network-based (220)
                policy_name = policy_info['name']
                if policy_name not in processed_network:
                    epmp_policy = create_network_policy(policy_info, app_group_info)
                    add_policy_with_id_check(epmp_policy)
                    processed_network.add(policy_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(policy_info['action'], f'Unknown({policy_info["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    logging.info(f'✅ Created Network policy: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                    
            elif epmp_policy_type == 24:  # Software distribution (242)
                if policy_info['internal_type'] == '242':
                    name = policy_info['name']
                    if name not in processed_software_dist:
                        child_policy = software_dist_groups.get(name, {}).get('244')
                        
                        epmp_policy = create_software_distribution_policy(policy_info, app_group_info, child_policy)
                        add_policy_with_id_check(epmp_policy)
                        processed_software_dist.add(name)
                        
                        action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                        child_action_name = action_names.get(epmp_policy.get('ChildAction', 1), 'Allow')
                        logging.info(f'✅ Created Software Distribution policy: {epmp_policy["Name"]} (Action: Allow, Installed Apps: {child_action_name})')
                        
            elif epmp_policy_type is None:
                logging.info(f'Policy type {policy_info["internal_type"]} is set to be skipped')
            else:
                logging.warning(f'Unknown policy type {epmp_policy_type} for policy {policy_info["name"]}')
                
        except Exception as e:
            logging.error(f'❌ Error processing policy "{policy_info["name"]}": {str(e)}', exc_info=True)
    
    # Log skipped policies summary
    if skipped_policies:
        logging.info(f'SUMMARY: Skipped {len(skipped_policies)} "Installed by/from" policies that were merged')
    
    # Final ID uniqueness check
    final_ids = [p['Id'] for p in epmp_policies]
    if len(final_ids) != len(set(final_ids)):
        logging.error('FINAL CHECK: Still have duplicate IDs!')
        id_counts = {}
        for policy_id in final_ids:
            id_counts[policy_id] = id_counts.get(policy_id, 0) + 1
        duplicates = [pid for pid, count in id_counts.items() if count > 1]
        logging.error(f'Duplicate IDs: {duplicates}')
    else:
        logging.info(f'FINAL CHECK: All {len(final_ids)} policy IDs are unique ✓')
    
    # Create EPMP structure
    epmp_data = {
        'Policies': epmp_policies,
        'AppGroups': [],
        'TrustSoftwareDistributors': [],
        'UserAccessTokens': [],
        'EndUserUIs': []
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
        if policy['PolicyType'] == 24:
            child_action = policy.get('ChildAction')
            child_action_counts[child_action] = child_action_counts.get(child_action, 0) + 1
    
    if child_action_counts:
        logging.info('Software Distribution Installed Applications action distribution:')
        for action, count in child_action_counts.items():
            action_name = action_names.get(action, f'Action {action}')
            logging.info(f'  - {action_name}: {count}')
    
    return epmp_data

def create_separate_source_files(epmp_data, base_output_file):
    """Source tipine göre ayrı EPMP dosyaları oluştur"""
    try:
        base_path = os.path.splitext(base_output_file)[0]
        
        policy_groups = {
            'publisher': [],
            'network': [],
            'software_dist': [],
            'product': []
        }
        
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
        
        type_names = {
            'publisher': 'Publisher-based',
            'network': 'Network-based',
            'software_dist': 'Software Distribution',
            'product': 'Product-based'
        }
        
        for group_key, policies in policy_groups.items():
            if policies:
                separate_data = {
                    'Policies': policies,
                    'AppGroups': [],
                    'TrustSoftwareDistributors': [],
                    'UserAccessTokens': [],
                    'EndUserUIs': []
                }
                
                output_filename = f"{base_path}_{group_key}.epmp"
                with open(output_filename, 'w', encoding='utf-8') as f:
                    json.dump(separate_data, f, indent=2, ensure_ascii=False)
                
                logging.info(f'Created {type_names[group_key]} file: {output_filename} ({len(policies)} policies)')
        
        logging.info('Successfully created separate source type files')
        
    except Exception as e:
        logging.error(f'Error creating separate source files: {str(e)}', exc_info=True)

def convert_file(input_file, output_file):
    """VFP dosyasını EPMP formatına çevir"""
    try:
        logging.info(f'Starting conversion from {input_file} to {output_file}')
        
        if not os.path.exists(input_file):
            logging.error(f'Input file not found: {input_file}')
            return False
        
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
            logging.error('Could not read file with any encoding')
            return False
        
        epmp_data = convert_vfp_trusted_sources_to_epmp(vfp_content)
        if epmp_data is None:
            return False
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(epmp_data, f, indent=2, ensure_ascii=False)
            logging.info(f'Successfully wrote main output file: {output_file}')
        
        create_separate_source_files(epmp_data, output_file)
        
        return True
    except Exception as e:
        logging.error(f'Error during conversion: {str(e)}', exc_info=True)
        return False

def validate_output(output_file):
    """Output dosyasını validate et"""
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        required_keys = ['Policies', 'AppGroups', 'TrustSoftwareDistributors', 'UserAccessTokens']
        for key in required_keys:
            if key not in data:
                logging.error(f'Missing required key: {key}')
                return False
        
        policies = data.get('Policies', [])
        if not isinstance(policies, list):
            logging.error('Policies must be a list')
            return False
        
        for policy in policies:
            if not isinstance(policy, dict):
                logging.error('Each policy must be a dictionary')
                return False
            
            required_policy_keys = ['Id', 'Name', 'PolicyType', 'Action']
            for key in required_policy_keys:
                if key not in policy:
                    logging.error(f'Missing required policy key: {key}')
                    return False
        
        logging.info(f'Output validation successful: {len(policies)} policies')
        return True
    except Exception as e:
        logging.error(f'Error validating output: {str(e)}')
        return False

def main():
    """Main function"""
    print('VFP to EPMP Trusted Sources Converter')
    print('=====================================')
    
    log_file = setup_logging()
    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = input('Enter VFP input file path: ').strip().strip('"')
    
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_file = f'{base_name}_trusted_sources.epmp'
    
    print(f'\n📁 Input file: {input_file}')
    print(f'📄 Output file: {output_file}')
    print(f'📋 Log file: {log_file}')
    
    if convert_file(input_file, output_file):
        if validate_output(output_file):
            print(f'\n✅ Trusted Sources conversion completed successfully!')
            print(f'📁 Log file: {log_file}')
            print(f'📄 Main output file: {output_file}')
            print(f'\n📊 Created separate files by source type:')
            
            base_path = os.path.splitext(output_file)[0]
            separate_files = []
            
            for suffix in ['_publisher', '_network', '_software_dist', '_product']:
                separate_file = f"{base_path}{suffix}.epmp"
                if os.path.exists(separate_file):
                    separate_files.append(separate_file)
            
            for separate_file in separate_files:
                file_size = os.path.getsize(separate_file)
                print(f'   📄 {os.path.basename(separate_file)} ({file_size:,} bytes)')
            
            print(f'\nThe converter has created EPMP Trusted Source policies:')
            print(f'  - Publisher-based policies (PolicyType 29) with Source Application Types from 281')
            print(f'  - Product-based policies (PolicyType 30) with Source Application Types from 231')
            print(f'  - Network-based policies (PolicyType 27)')
            print(f'  - Software Distribution policies (PolicyType 24)')
            print(f'\n💡 Use separate files for easier debugging and testing!')
        else:
            print(f'\n⚠️  Conversion completed but output validation failed.')
            print(f'📁 Log file: {log_file}')
    else:
        print(f'\n❌ Conversion failed.')
        print(f'📁 Log file: {log_file}')

if __name__ == '__main__':
    main()
