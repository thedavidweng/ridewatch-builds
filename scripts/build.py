#!/usr/bin/env python3
"""Build private source on an ephemeral runner; publish only age ciphertext."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


def main():
    os.umask(0o077)
    sha = os.environ.get('SOURCE_SHA', '')
    recipient = os.environ.get('ARTIFACT_RECIPIENT', '')
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or not recipient.startswith('age1'):
        print('::error::A full source commit SHA and age recipient are required.')
        return 1
    sealed = Path('sealed').resolve()
    sealed.mkdir(exist_ok=True)
    # No signing or checkout credentials are inherited by source build scripts.
    env = {k: v for k, v in os.environ.items() if k not in {
        'SOURCE_DEPLOY_KEY', 'IOS_CERTIFICATE_P12_BASE64',
        'IOS_CERTIFICATE_PASSWORD', 'IOS_ADHOC_PROFILE_BASE64',
        'GOOGLE_IOS_CLIENT_ID', 'GH_TOKEN', 'GITHUB_TOKEN'}}
    keychain = None
    installed_profile = None
    previous_keychains = None
    success = False
    phase = 'preflight'
    with tempfile.TemporaryDirectory(prefix='ridewatch-private-') as directory:
        work = Path(directory)
        log_path = work / 'build.log'
        with log_path.open('wb') as log:
            def run(args, *, cwd=None, capture=False, input=None, custom_env=None):
                result = subprocess.run(args, cwd=cwd, env=custom_env or env,
                                        input=input, stdout=subprocess.PIPE if capture else log,
                                        stderr=log)
                if result.returncode:
                    raise RuntimeError('Command failed in ' + phase)
                return result.stdout

            try:
                phase = 'checkout'
                key = work / 'source-key'
                key.write_text(os.environ['SOURCE_DEPLOY_KEY'].rstrip() + '\n')
                known = work / 'known-hosts'
                with urllib.request.urlopen('https://api.github.com/meta', timeout=30) as response:
                    metadata = json.load(response)
                known.write_text(''.join('github.com ' + value + '\n' for value in metadata['ssh_keys']))
                git_env = dict(env, GIT_SSH_COMMAND=f'ssh -i {shlex.quote(str(key))} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={shlex.quote(str(known))}')
                source = work / 'source'
                run(['git', 'clone', '--single-branch', '--branch', 'main',
                     'ssh://' + 'git' + '@' + 'github.com/thedavidweng/RideWatch.git', str(source)], custom_env=git_env)
                run(['git', 'merge-base', '--is-ancestor', sha, 'origin/main'], cwd=source)
                run(['git', 'checkout', '--detach', sha], cwd=source)
                key.unlink()
                shutil.rmtree(source / '.git')

                phase = 'signing setup'
                p12 = work / 'identity.p12'
                p12.write_bytes(base64.b64decode(os.environ['IOS_CERTIFICATE_P12_BASE64'], validate=True))
                profile = work / 'adhoc.mobileprovision'
                profile.write_bytes(base64.b64decode(os.environ['IOS_ADHOC_PROFILE_BASE64'], validate=True))
                provisioning = plistlib.loads(run(['security', 'cms', '-D', '-i', str(profile)], capture=True))
                entitlements = provisioning['Entitlements']
                assert provisioning['TeamIdentifier'] == ['NCFNX3LJ83']
                assert entitlements['application-identifier'] == 'NCFNX3LJ83.app.ridewatch.transit'
                assert provisioning.get('ProvisionedDevices') and not provisioning.get('ProvisionsAllDevices')
                assert not entitlements.get('get-task-allow') and not entitlements.get('beta-reports-active')
                import datetime
                assert provisioning['ExpirationDate'] > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                certificate_sha1 = hashlib.sha1(provisioning['DeveloperCertificates'][0]).hexdigest().upper()
                previous_keychains = shlex.split(run(['security', 'list-keychains', '-d', 'user'], capture=True).decode())
                keychain = work / 'signing.keychain-db'
                password = os.urandom(32).hex()
                run(['security', 'create-keychain', '-p', password, str(keychain)])
                run(['security', 'set-keychain-settings', '-lut', '3600', str(keychain)])
                run(['security', 'unlock-keychain', '-p', password, str(keychain)])
                run(['security', 'import', str(p12), '-k', str(keychain), '-P',
                     os.environ['IOS_CERTIFICATE_PASSWORD'], '-T', '/usr/bin/codesign'])
                run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:',
                     '-s', '-k', password, str(keychain)])
                run(['security', 'list-keychains', '-d', 'user', '-s', str(keychain), *previous_keychains])
                p12.unlink()
                profile_dir = Path.home() / 'Library/Developer/Xcode/UserData/Provisioning Profiles'
                profile_dir.mkdir(parents=True, exist_ok=True)
                installed_profile = profile_dir / (provisioning['UUID'] + '.mobileprovision')
                if installed_profile.exists():
                    installed_profile = None
                    raise RuntimeError('Refusing to replace existing profile')
                shutil.copyfile(profile, installed_profile)

                phase = 'project generation'
                ios = source / 'apps/ios'
                spec = json.loads(run(['ruby', '-rpsych', '-rjson', '-e',
                                      'puts JSON.generate(Psych.safe_load(File.read(ARGV[0]), aliases: true))',
                                      str(ios / 'project.yml')], capture=True))
                app_target = spec['targets']['RideWatch']
                app_target['dependencies'] = [d for d in app_target['dependencies'] if d.get('target') != 'RideWatchWidgets']
                del spec['targets']['RideWatchWidgets']
                release = app_target['settings']['configs']['Release']
                release.update(CODE_SIGN_STYLE='Manual', CODE_SIGN_IDENTITY=certificate_sha1,
                               PROVISIONING_PROFILE_SPECIFIER=provisioning['Name'],
                               RIDEWATCH_API_BASE_URL='https://ridewatch-api.davidweng.workers.dev')
                google = os.environ.get('GOOGLE_IOS_CLIENT_ID', '')
                if google:
                    release['GOOGLE_IOS_CLIENT_ID'] = google
                    release['GOOGLE_IOS_URL_SCHEME'] = '.'.join(reversed(google.split('.')))
                spec_path = ios / 'ci-main-only.json'
                spec_path.write_text(json.dumps(spec))
                run(['xcodegen', 'generate', '--spec', str(spec_path), '--project', str(ios), '--quiet'])

                phase = 'archive'
                archive = work / 'RideWatch.xcarchive'
                run(['xcodebuild', '-project', str(ios / 'RideWatch.xcodeproj'), '-scheme', 'RideWatch',
                     '-configuration', 'Release', '-destination', 'generic/platform=iOS',
                     '-archivePath', str(archive), 'archive'])
                phase = 'export'
                options = work / 'ExportOptions.plist'
                options.write_bytes(plistlib.dumps({'method': 'release-testing', 'teamID': 'NCFNX3LJ83',
                    'signingStyle': 'manual', 'signingCertificate': certificate_sha1,
                    'provisioningProfiles': {'app.ridewatch.transit': provisioning['UUID']},
                    'manageAppVersionAndBuildNumber': False, 'destination': 'export'}))
                export = work / 'export'
                run(['xcodebuild', '-exportArchive', '-archivePath', str(archive),
                     '-exportPath', str(export), '-exportOptionsPlist', str(options)])
                phase = 'verification'
                ipas = list(export.glob('*.ipa'))
                assert len(ipas) == 1
                unpacked = work / 'verify'
                with zipfile.ZipFile(ipas[0]) as z:
                    z.extractall(unpacked)
                apps = list((unpacked / 'Payload').glob('*.app'))
                assert len(apps) == 1 and not list(apps[0].rglob('*.appex'))
                run(['codesign', '--verify', '--deep', '--strict', str(apps[0])])
                signed = plistlib.loads(run(['codesign', '-d', '--entitlements', ':-', str(apps[0])], capture=True))
                assert signed['application-identifier'] == entitlements['application-identifier']
                assert not signed.get('beta-reports-active') and not signed.get('get-task-allow')
                for field in ['aps-environment', 'com.apple.developer.applesignin', 'com.apple.security.application-groups']:
                    assert signed.get(field) == entitlements.get(field)
                embedded = plistlib.loads(run(['security', 'cms', '-D', '-i', str(apps[0] / 'embedded.mobileprovision')], capture=True))
                assert set(embedded['ProvisionedDevices']) == set(provisioning['ProvisionedDevices'])
                info = plistlib.loads((apps[0] / 'Info.plist').read_bytes())
                assert info['RWAPIBaseURL'] == release['RIDEWATCH_API_BASE_URL']
                receipt = work / 'verification.json'
                receipt.write_text(json.dumps({'sourceSha': sha, 'bundleId': info['CFBundleIdentifier'],
                    'version': info['CFBundleShortVersionString'], 'build': info['CFBundleVersion'],
                    'ipaSha256': hashlib.sha256(ipas[0].read_bytes()).hexdigest(),
                    'deviceCount': len(embedded['ProvisionedDevices']), 'googleConfigured': bool(google),
                    'extensions': 0, 'signatureVerified': True}, indent=2))
                phase = 'encryption'
                for path, name in [(ipas[0], 'RideWatch.ipa.age'), (receipt, 'verification.json.age')]:
                    run(['age', '-r', recipient, '-o', str(sealed / name), str(path)])
                success = True
            except Exception:
                # Never echo exceptions from private source, Xcode, or signing tools.
                print('::error::Private build failed during ' + phase + '; inspect encrypted diagnostics.')
            finally:
                if keychain:
                    subprocess.run(['security', 'delete-keychain', str(keychain)], stdout=log, stderr=log)
                if previous_keychains is not None:
                    subprocess.run(['security', 'list-keychains', '-d', 'user', '-s', *previous_keychains], stdout=log, stderr=log)
                if installed_profile:
                    installed_profile.unlink(missing_ok=True)
                log.flush()
                enc = subprocess.run(['age', '-r', recipient, '-o', str(sealed / 'build.log.age'), str(log_path)], stdout=log, stderr=log)
                success = success and enc.returncode == 0
    print('Signed IPA verified; only encrypted outputs retained.' if success else 'Build did not complete.')
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
