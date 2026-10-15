import os
import sys
import shutil
import uuid
import re

# Add current dir to sys.path
sys.path.insert(0, os.path.abspath('.'))

from app import (
    app,
    update_android_config,
    update_windows_config,
    update_ios_config,
    update_macos_config,
    update_linux_config,
    rename_app
)

def bool_to_dart(val):
    return 'true' if val else 'false'


platforms_to_test = [
    ('android', ['android']),
    ('android_aab', ['android_aab']),
    ('windows', ['windows']),
    ('ios', ['ios']),
    ('macos', ['macos']),
    ('linux', ['linux']),
]

test_base_dir = os.path.abspath('test_build_runs')
os.makedirs(test_base_dir, exist_ok=True)

success_count = 0

for plat_name, plat_list in platforms_to_test:
    print(f"\n==========================================")
    print(f"Testing configuration generation for: {plat_name}")
    print(f"==========================================")

    build_id = f"test_{plat_name}_{str(uuid.uuid4())[:8]}"
    build_dir = os.path.join(test_base_dir, build_id)
    project_dir = os.path.join(build_dir, 'project')
    os.makedirs(build_dir, exist_ok=True)

    config = {
        'app_name': f"TestApp_{plat_name}",
        'app_description': "Test Application for all platforms",
        'app_version': "1.0.0",
        'build_number': "1",
        'package_name': "com.test.app",
        'web_url': "https://example.com",
        'platforms': plat_list,
        'allow_zoom': True,
        'enable_javascript': True,
        'enable_dom_storage': True,
        'enable_geolocation': True,
        'enable_pull_refresh': True,
        'show_navigation': True,
        'show_navigation_2': True,
        'enable_file_access': True,
        'enable_cache': True,
        'enable_media_autoplay': False,
        'enable_camera': True,
        'enable_microphone': True,
        'enable_ssl_pinning': False,
        'enable_biometrics': False,
        'enable_app_lock': False,
        'enable_secure_storage': False,
        'enable_splash_screen': False,
        'enable_error_page': False,
    }

    try:
        # Copy template
        shutil.copytree(app.config['FLUTTER_TEMPLATE'], project_dir)

        # Update main.dart
        main_dart_path = os.path.join(project_dir, 'lib', 'main.dart')
        with open(main_dart_path, 'r', encoding='utf-8') as f:
            content = f.read()

        content = content.replace('{{APP_NAME}}', config['app_name'])
        content = content.replace('{{APP_URL}}', config['web_url'])

        # Verify all regex substitutions in main.dart
        replacements = [
            (r'static const bool ALLOW_ZOOM = \w+;', f'static const bool ALLOW_ZOOM = {bool_to_dart(config["allow_zoom"])};'),
            (r'static const bool ENABLE_JAVASCRIPT = \w+;', f'static const bool ENABLE_JAVASCRIPT = {bool_to_dart(config["enable_javascript"])};'),
            (r'static const bool ENABLE_DOM_STORAGE = \w+;', f'static const bool ENABLE_DOM_STORAGE = {bool_to_dart(config["enable_dom_storage"])};'),
            (r'static const bool ENABLE_GEOLOCATION = \w+;', f'static const bool ENABLE_GEOLOCATION = {bool_to_dart(config["enable_geolocation"])};'),
            (r'static const bool ENABLE_PULL_TO_REFRESH = \w+;', f'static const bool ENABLE_PULL_TO_REFRESH = {bool_to_dart(config["enable_pull_refresh"])};'),
            (r'static const bool SHOW_NAVIGATION_BAR = \w+;', f'static const bool SHOW_NAVIGATION_BAR = {bool_to_dart(config["show_navigation"])};'),
            (r'static const bool SHOW_NAVIGATION_BAR_2 = \w+;', f'static const bool SHOW_NAVIGATION_BAR_2 = {bool_to_dart(config["show_navigation_2"])};'),
            (r'static const bool ENABLE_FILE_ACCESS = \w+;', f'static const bool ENABLE_FILE_ACCESS = {bool_to_dart(config["enable_file_access"])};'),
            (r'static const bool ENABLE_CACHE = \w+;', f'static const bool ENABLE_CACHE = {bool_to_dart(config["enable_cache"])};'),
            (r'static const bool ENABLE_MEDIA_AUTOPLAY = \w+;', f'static const bool ENABLE_MEDIA_AUTOPLAY = {bool_to_dart(config["enable_media_autoplay"])};'),
            (r'static const bool ENABLE_CAMERA = \w+;', f'static const bool ENABLE_CAMERA = {bool_to_dart(config["enable_camera"])};'),
            (r'static const bool ENABLE_MICROPHONE = \w+;', f'static const bool ENABLE_MICROPHONE = {bool_to_dart(config["enable_microphone"])};'),
        ]

        for pattern, repl in replacements:
            new_content, count = re.subn(pattern, repl, content)
            if count == 0:
                raise ValueError(f"Pattern '{pattern}' not matched in main.dart!")
            content = new_content

        with open(main_dart_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Platform specific updates
        if 'android' in plat_list or 'android_aab' in plat_list:
            update_android_config(project_dir, config)
            print("  [OK] Android configuration updated successfully")

        if 'windows' in plat_list:
            update_windows_config(project_dir, config)
            print("  [OK] Windows configuration updated successfully")

        if 'ios' in plat_list:
            update_ios_config(project_dir, config)
            print("  [OK] iOS configuration updated successfully")

        if 'macos' in plat_list:
            update_macos_config(project_dir, config)
            print("  [OK] macOS configuration updated successfully")

        if 'linux' in plat_list:
            update_linux_config(project_dir, config)
            print("  [OK] Linux configuration updated successfully")

        # Package name
        rename_app(project_dir, config['app_name'], config['package_name'])
        print("  [OK] Package name updated successfully")

        # Pubspec
        pubspec_path = os.path.join(project_dir, 'pubspec.yaml')
        with open(pubspec_path, 'r', encoding='utf-8') as f:
            pubspec = f.read()

        clean_app_name = re.sub(r'[^a-z0-9_]', '_', config['app_name'].lower()).strip('_')
        pubspec = re.sub(r'^name:\s+.*$', f"name: {clean_app_name}", pubspec, flags=re.MULTILINE)
        pubspec = re.sub(r'^version:\s+.*$', f"version: {config['app_version']}+{config['build_number']}", pubspec, flags=re.MULTILINE)

        with open(pubspec_path, 'w', encoding='utf-8') as f:
            f.write(pubspec)
        print("  [OK] pubspec.yaml updated successfully")

        # Verify main.dart syntax checks
        with open(main_dart_path, 'r', encoding='utf-8') as f:
            final_dart = f.read()

        assert 'SHOW_NAVIGATION_BAR_2 = true;' in final_dart, "SHOW_NAVIGATION_BAR_2 not injected correctly"
        assert 'SHOW_NAVIGATION_BAR = true;' in final_dart, "SHOW_NAVIGATION_BAR not injected correctly"
        assert 'Icons.arrow_back_ios_new_rounded' not in final_dart, "Found bad icon!"
        assert 'additionalBrowserArguments' not in final_dart, "Found bad parameter!"

        print(f"  --> PASSED: {plat_name} build package prepared with 0 errors!")
        success_count += 1

    except Exception as e:
        print(f"  [X] FAILED on {plat_name}: {e}")
        import traceback
        traceback.print_exc()

# Cleanup test directory
shutil.rmtree(test_base_dir, ignore_errors=True)

print(f"\n==========================================")
print(f"FINAL RESULT: {success_count}/{len(platforms_to_test)} Platforms PASSED!")
print(f"==========================================")
