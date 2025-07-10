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
    
    for policy in root.findall('.//Policy'):
        gpid = policy.get('gpid', '').strip('{}')
        if not gpid:
            continue
            
        policy_info = {
            'gpid': gpid,
            'name': policy.get('name', ''),
            'action': int(policy.get('action', '1')),
            'description': policy.get('description', ''),
            'internal_type': policy.get('internalType', ''),
            'target_app_groups': []
        }
        
        # Parse target application groups
        for target in policy.findall('.//ApplicationGroup'):
            app_group_id = target.get('id', '').strip('{}')
            if app_group_id:
                policy_info['target_app_groups'].append(app_group_id)
        
        policies[gpid] = policy_info
        
    return policies

def parse_application_groups(root):
    """Parse VFP application groups from XML"""
    app_groups = {}
    
    for app_group in root.findall('.//ApplicationGroup'):
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
        
    return app_groups

def get_epmp_action(vfp_action, policy_type):
    """VFP action'ından EPMP action'ına çevir"""
    # VFP actions: 0=Off, 1=Allow, 2=Deny, 3=Require justification, 4=Elevate
    # EPMP actions: 0=Off, 1=Allow, 2=Deny, 3=Require justification, 4=Elevate
    return vfp_action  # Direct mapping

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
        # '231': Skip - "Installed from Product" policies are merged, not converted separately
        '285': 30   # Product/Service → Product-based policy
    }
    
    # internalType="244" ve "231" için None döndür - bu policy'ler ayrı convert edilmez
    if internal_type in ['244', '231']:
        return None
    
    return type_mapping.get(internal_type, 29)  # Default to signature policy

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
    
    # Her policy için benzersiz UUID'ler oluştur
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    # Debug log ekle
    logging.info(f'Creating Publisher policy IDs: Main={main_policy_id}, Linked1={linked_policy_1_id}, Linked2={linked_policy_2_id}')
    
    policy = {
        'Id': main_policy_id,
        'Name': f"Signature '{publisher_content}'" if publisher_content else policy_info['name'],
        'PolicyType': 29,
        'Action': action,
        'Description': policy_info.get('description', ''),
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
            'compareAs': 0,  # VFP'de "exact" → EPMP'de 0
            'caseSensitive': True,  # VFP'den alınıyor
            'isEmpty': False
        },
        'ApplyPolicyOnInstalledApplications': True,
        'ApplyPolicyOnLocalHardDrivesOnly': False,
        'IsActive': True,
        'IsTargetedEXE': True,
        'IsTargetedDLL': True,
        'IsTargetedMSI': True,
        'IsTargetedMSU': True,
        'IsTargetedScript': True,
        'IsTargetedCOM': True,
        'IsTargetedActiveX': True
    }
    
    # UAC Replace alanları sadece Action=Elevate (4) olduğunda eklenir
    if action == 4:  # Elevate
        ui_replace_uac_id = str(uuid4())
        ui_replace_uac_admin_id = str(uuid4())
        ui_shell_extension_id = str(uuid4())
        
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False,
            'UIReplaceUAC': {'Id': ui_replace_uac_id, 'AllowedDialogType': 'ElevateOnDemand'},
            'UIReplaceUacAdmin': {'Id': ui_replace_uac_admin_id, 'AllowedDialogType': 'ElevateOnDemand'},
            'UIShellExtension': {'Id': ui_shell_extension_id, 'AllowedDialogType': 'ElevateOnDemand'}
        })
    
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
    
    # Her policy için benzersiz UUID'ler oluştur
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    # Debug log ekle
    logging.info(f'Creating Network policy IDs: Main={main_policy_id}, Linked1={linked_policy_1_id}, Linked2={linked_policy_2_id}')

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
    
    # UAC Replace alanları sadece Action=Elevate (4) olduğunda eklenir
    if action == 4:  # Elevate
        ui_replace_uac_id = str(uuid4())
        ui_replace_uac_admin_id = str(uuid4())
        ui_shell_extension_id = str(uuid4())
        
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False,
            'UIReplaceUAC': {'Id': ui_replace_uac_id, 'AllowedDialogType': 'ElevateOnDemand'},
            'UIReplaceUacAdmin': {'Id': ui_replace_uac_admin_id, 'AllowedDialogType': 'ElevateOnDemand'},
            'UIShellExtension': {'Id': ui_shell_extension_id, 'AllowedDialogType': 'ElevateOnDemand'}
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
    
    # Her policy için benzersiz UUID'ler oluştur
    main_policy_id = str(uuid4())
    linked_policy_id = str(uuid4())
    
    # Debug log ekle
    logging.info(f'Creating Product policy IDs: Main={main_policy_id}, Linked={linked_policy_id}')

    policy = {
        'Id': main_policy_id,
        'Name': policy_info['name'],  # Orijinal policy name'i koru
        'PolicyType': 30,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_id, 'InternalId': 0, 'PolicyType': 285}  # Sadece 285 var
        ],
        'Audit': False,
        'ProductName': product_name,
        'ProductCompareAs': 0,  # EPMP örneğinde 0
        'Publisher': {
            '@type': 'Publisher',
            'separator': ';',
            'signatureLevel': 2,
            'content': product_name,  # ProductName Publisher content olarak da kullanılıyor
            'compareAs': 0,
            'caseSensitive': True,
            'isEmpty': False
        },
        'IsActive': True,
        'IsTargetedEXE': True,
        'IsTargetedDLL': True,
        'IsTargetedMSI': True
        # IsTargetedMSU, IsTargetedScript, IsTargetedCOM, IsTargetedActiveX yok
    }
    
    # UAC Replace alanları sadece Action=Elevate (4) olduğunda eklenir
    if action == 4:  # Elevate
        ui_replace_uac_id = str(uuid4())
        ui_replace_uac_admin_id = str(uuid4())
        ui_shell_extension_id = str(uuid4())
        
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False,
            'UIReplaceUAC': {'Id': ui_replace_uac_id, 'AllowedDialogType': 'ElevateOnDemand'},
            'UIReplaceUacAdmin': {'Id': ui_replace_uac_admin_id, 'AllowedDialogType': 'ElevateOnDemand'},
            'UIShellExtension': {'Id': ui_shell_extension_id, 'AllowedDialogType': 'ElevateOnDemand'}
        })
    
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
    
    # Her policy için benzersiz UUID'ler oluştur
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    # Debug log ekle
    logging.info(f'Creating Software Distribution policy IDs: Main={main_policy_id}, Linked1={linked_policy_1_id}, Linked2={linked_policy_2_id}')
    
    # Base policy structure
    policy = {
        'Id': main_policy_id,
        'Name': policy_name,  # Orijinal policy name'i koru
        'PolicyType': 24,
        'Action': action,  # Ana action her zaman Allow
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 242},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 244}
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
            child_ui_replace_uac_id = str(uuid4())
            child_ui_replace_uac_admin_id = str(uuid4())
            child_ui_shell_extension_id = str(uuid4())
            
            policy.update({
                'ChildReplaceUAC': True,
                'ChildReplaceUacAdmin': True,
                'ChildShellExtension': False,
                'ChildUIReplaceUAC': {'Id': child_ui_replace_uac_id, 'AllowedDialogType': 'ElevateOnDemand'},
                'ChildUIReplaceUacAdmin': {'Id': child_ui_replace_uac_admin_id, 'AllowedDialogType': 'ElevateOnDemand'},
                'ChildUIShellExtension': {'Id': child_ui_shell_extension_id, 'AllowedDialogType': 'ElevateOnDemand'}
            })
    
    return policy

def convert_vfp_trusted_sources_to_epmp(vfp_content):
    """VFP Trusted Sources'ı EPMP formatına çevir"""
    root = ET.fromstring(vfp_content)
    logging.info('Successfully parsed VFP XML content')
    
    # Parse policies and application groups
    policies = parse_policies(root)
    app_groups = parse_application_groups(root)
    
    logging.info(f'Found {len(policies)} policies and {len(app_groups)} application groups')
    
    # Software Distribution policy'lerini gruplayalım
    software_dist_groups = {}
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] in ['242', '244']:  # Software Distribution types
            # Policy name'den software name'i çıkar
            name = policy_info['name']
            if policy_info['internal_type'] == '244' and name.startswith('Installed by: '):
                software_name = name[14:]  # "Installed by: " prefix'ini kaldır
            elif policy_info['internal_type'] == '242':
                software_name = name
            else:
                software_name = name
            
            if software_name not in software_dist_groups:
                software_dist_groups[software_name] = {}
            
            software_dist_groups[software_name][policy_info['internal_type']] = policy_info
            logging.info(f'Grouped software distribution policy: {name} -> group "{software_name}" (type {policy_info["internal_type"]})')
    
    # Product policy'lerini gruplayalım  
    product_groups = {}
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] in ['230', '231', '285']:  # Product types
            # Policy name'den product name'i çıkar
            name = policy_info['name']
            if policy_info['internal_type'] == '231' and name.startswith('Installed from: '):
                product_name = name[15:]  # "Installed from: " prefix'ini kaldır
            elif policy_info['internal_type'] in ['230', '285']:
                product_name = name
            else:
                product_name = name
            
            if product_name not in product_groups:
                product_groups[product_name] = {}
            
            product_groups[product_name][policy_info['internal_type']] = policy_info
            logging.info(f'Grouped product policy: {name} -> group "{product_name}" (type {policy_info["internal_type"]})')
    
    # Convert each policy to EPMP format
    epmp_policies = []
    processed_software_dist = set()
    processed_product = set()
    skipped_policies = []
    
    for gpid, policy_info in policies.items():
        logging.info(f'Processing policy: {policy_info["name"]} (Type: {policy_info["internal_type"]}, Action: {policy_info["action"]})')
        
        # Skip "Installed by" and "Installed from" policies COMPLETELY
        if policy_info['internal_type'] in ['244', '231']:
            policy_type_name = 'Installed by' if policy_info['internal_type'] == '244' else 'Installed from'
            logging.info(f'SKIPPING "{policy_type_name}" policy: {policy_info["name"]} - will be merged with main policy')
            skipped_policies.append(policy_info['name'])
            continue
        
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
            # Software Distribution için sadece ana policy (242) işle
            if policy_info['internal_type'] == '242':
                name = policy_info['name']
                if name not in processed_software_dist:
                    # Ana policy ve "Installed by" policy'yi birleştir
                    child_policy = software_dist_groups.get(name, {}).get('244')
                    
                    epmp_policy = create_software_distribution_policy(policy_info, app_group_info, child_policy)
                    epmp_policies.append(epmp_policy)
                    processed_software_dist.add(name)
                    
                    # Action mapping'i log'a ekle
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    child_action_name = action_names.get(epmp_policy.get('ChildAction', 1), 'Allow')
                    logging.info(f'Created Software Distribution policy: {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: Allow, Installed Apps: {child_action_name})')
                else:
                    logging.info(f'Software Distribution policy already processed: {name}')
                    continue
            else:
                # İçine girmemesi gereken dal - debug için log ekle
                logging.warning(f'Unexpected software distribution internal type {policy_info["internal_type"]} for policy {policy_info["name"]}')
                continue
        elif epmp_policy_type == 30:  # Product-based
            # Product için sadece ana policy'leri (230, 285) işle
            if policy_info['internal_type'] in ['230', '285']:
                name = policy_info['name']
                if name not in processed_product:
                    # Ana policy ve "Installed from" policy'yi birleştir (eğer varsa)
                    # Product policy'lerde normalde child action yok ama bilgi için merge edebiliriz
                    child_policy = product_groups.get(name, {}).get('231')
                    
                    epmp_policy = create_product_policy(policy_info, app_group_info)
                    epmp_policies.append(epmp_policy)
                    processed_product.add(name)
                    
                    # Action mapping'i log'a ekle
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(policy_info['action'], f'Unknown({policy_info["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    
                    if child_policy:
                        logging.info(f'Created Product policy (merged with "Installed from"): {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: {vfp_action_name} → {epmp_action_name})')
                    else:
                        logging.info(f'Created Product policy: {epmp_policy["Name"]} (PolicyType: {epmp_policy["PolicyType"]}, Action: {vfp_action_name} → {epmp_action_name})')
                else:
                    logging.info(f'Product policy already processed: {name}')
                    continue
            else:
                # İçine girmemesi gereken dal - debug için log ekle
                logging.warning(f'Unexpected product internal type {policy_info["internal_type"]} for policy {policy_info["name"]}')
                continue
        else:
            logging.warning(f'Unknown policy type {epmp_policy_type} for policy {policy_info["name"]}')
            continue
    
    # Log skipped policies summary
    if skipped_policies:
        logging.info(f'SUMMARY: Skipped {len(skipped_policies)} "Installed by/from" policies that were merged:')
        for skipped in skipped_policies:
            logging.info(f'  - {skipped}')
    
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

def validate_output(output_file):
    """Output dosyasını validate et"""
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Basic structure check
        required_keys = ['Policies', 'AppGroups', 'TrustSoftwareDistributors', 'UserAccessTokens']
        for key in required_keys:
            if key not in data:
                logging.error(f'Missing required key in output: {key}')
                return False
        
        # Policy validation
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
    
    # Setup logging
    log_file = setup_logging()
    
    # Get input parameters
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = input('Enter VFP input file path: ').strip().strip('"')
    
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        # Auto-generate output filename
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_file = f'{base_name}_trusted_sources.epmp'
    
    print(f'\n📁 Input file: {input_file}')
    print(f'📄 Output file: {output_file}')
    print(f'📋 Log file: {log_file}')
    
    # Convert file
    if convert_file(input_file, output_file):
        # Validate the output
        if validate_output(output_file):
            print(f'\n✅ Trusted Sources conversion completed successfully!')
            print(f'📁 Log file: {log_file}')
            print(f'📄 Main output file: {output_file}')
            print(f'\n📊 Created separate files by source type:')
            
            # Ayrı dosyaların listesini göster
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
            print(f'  - Publisher-based policies (PolicyType 29)')
            print(f'  - Network-based policies (PolicyType 27)')
            print(f'  - Software Distribution policies (PolicyType 24)')
            print(f'  - Product-based policies (PolicyType 30)')
            print(f'\n💡 Use separate files for easier debugging and testing!')
        else:
            print(f'\n⚠️  Conversion completed but output validation failed.')
            print(f'📁 Log file: {log_file}')
    else:
        print(f'\n❌ Conversion failed.')
        print(f'📁 Log file: {log_file}')

if __name__ == '__main__':
    main()