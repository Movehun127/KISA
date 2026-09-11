"""Small allowlisted Windows configuration transactions, with readback."""
import base64
import json
from .execution import run_ps

SMB_LIMITS = {'AutoDisconnectTimeout': 15, 'AutoDisconnectTimeoutInMinutesV1': 15,
              'AutoDisconnectTimeoutInSecondsV2': 900}
PROFILES = {'Domain', 'Private', 'Public'}


def read_smb():
    data = json.loads(run_ps('Get-SmbServerConfiguration | ConvertTo-Json -Compress'))
    if type(data.get('EnableForcedLogoff')) is not bool:
        raise ValueError('SMB forced logoff state unavailable')
    values = {'EnableForcedLogoff': data['EnableForcedLogoff']}
    for key in SMB_LIMITS:
        if key in data:
            if type(data[key]) is not int or data[key] < 0:
                raise ValueError('Invalid SMB timeout')
            values[key] = data[key]
    if len(values) == 1:
        raise ValueError('SMB idle timeout is not exposed on this Windows version')
    return values


def smb_compliant(values):
    return (values.get('EnableForcedLogoff') is True and len(values) > 1
            and all(type(v) is int and 0 <= v <= SMB_LIMITS[k]
                    for k, v in values.items() if k in SMB_LIMITS))


def smb_target(before):
    return {k: True if k == 'EnableForcedLogoff' else min(v, SMB_LIMITS[k])
            for k, v in before.items()}


def write_smb(values):
    if (not values or not set(values) <= set(SMB_LIMITS) | {'EnableForcedLogoff'}
            or type(values.get('EnableForcedLogoff')) is not bool):
        raise ValueError('Unsupported SMB settings')
    for k, v in values.items():
        if k in SMB_LIMITS and (type(v) is not int or not 0 <= v <= 4294967295):
            raise ValueError('Invalid SMB timeout')
    encoded = base64.b64encode(json.dumps(values).encode()).decode()
    run_ps("$v=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded +
           "')) | ConvertFrom-Json; $p=@{}; $cmd=Get-Command Set-SmbServerConfiguration; "
           "foreach($prop in $v.PSObject.Properties){ "
           "if(-not $cmd.Parameters.ContainsKey($prop.Name)){throw 'Unsupported SMB parameter'}; "
           "$p[$prop.Name]=$prop.Value }; Set-SmbServerConfiguration @p -Confirm:$false")


def read_firewall(store='PersistentStore'):
    if store not in ('PersistentStore', 'ActiveStore'):
        raise ValueError('Invalid policy store')
    rows = json.loads(run_ps('Get-NetFirewallProfile -PolicyStore ' + store +
        " | Select-Object Name,@{n='Enabled';e={$_.Enabled.ToString()}} | ConvertTo-Json -Compress"))
    if not isinstance(rows, list):
        raise ValueError('Firewall profile list incomplete')
    result = {r['Name']: r['Enabled'] for r in rows}
    if len(rows) != 3 or set(result) != PROFILES or any(v not in ('True', 'False', 'NotConfigured') for v in result.values()):
        raise ValueError('Firewall profile state incomplete')
    return result


def write_firewall(values, best_effort=False):
    if set(values) != PROFILES or any(v not in ('True', 'False', 'NotConfigured') for v in values.values()):
        raise ValueError('Invalid firewall profile state')
    # Only Enabled is changed; rules, default actions, ports and logging remain intact.
    failures = []
    for name, enabled in sorted(values.items()):
        try:
            run_ps(f'Set-NetFirewallProfile -PolicyStore PersistentStore -Profile {name} -Enabled {enabled}')
        except Exception as exc:
            if not best_effort:
                raise
            failures.append(f'{name}: {exc}')
    if failures:
        raise RuntimeError('; '.join(failures))
