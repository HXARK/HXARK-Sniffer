"""Portable capture receipts. Never export keys, endpoints or account data."""
import json
import os
from pathlib import Path
import re
import tempfile

from .capture_library import _regular, _hash
from .trust import APP_VERSION
from .updates import safe_store


def receipt_data(item, session, observation, context):
    receipt = item['receipt']
    counts = receipt['frames_by_direction']
    value = {
        'schema': 'hxark-capture-v1', 'tool': 'HXARK Sniffer', 'toolVersion': APP_VERSION,
        'pktSha256': receipt['pkt_sha256'], 'pktBytes': receipt['bytes'],
        'pktRecords': receipt['records'], 'clientBuild': receipt['build'],
        'clientImageSha256': observation['image_sha256'],
        'connectionIndex': receipt['connection_index'],
        'clientFrames': counts['client'], 'serverFrames': counts['server'],
        'authenticatedFrames': receipt['authenticated_frames'],
        'containerComplete': receipt['container_complete'],
        'transportComplete': receipt['transport_complete'],
        'sessionComplete': session['complete'],
        'terminationBasis': receipt['termination_basis'],
        'timeBasis': receipt['time_basis'], 'locale': receipt['locale'],
        'utcOffsetSeconds': receipt['utc_offset_seconds'],
        'localeSource': (context or {}).get('locale_source', 'unknown'),
        'uncapturedConnections': session['uncaptured_owned_connections'],
        'sessionErrorCount': len(session['errors']),
        'captureStatsStatus': session.get('capture_stats_status', 'unavailable'),
        'captureDroppedPackets': session.get('capture_dropped_packets'),
        'unsupportedConnections': session.get('unsupported_game_connections', 0),
    }
    for key in ('pktSha256', 'clientImageSha256'):
        if type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}', value[key]):
            raise ValueError('invalid_quality_hash')
    for key in ('pktBytes', 'pktRecords', 'clientBuild', 'connectionIndex', 'clientFrames',
                'serverFrames', 'authenticatedFrames', 'uncapturedConnections', 'sessionErrorCount',
                'unsupportedConnections'):
        if type(value[key]) is not int or not 0 <= value[key] < 2**63:
            raise ValueError('invalid_quality_count')
    # A compressed world frame may contain several exported PKT messages.
    status, dropped = value['captureStatsStatus'], value['captureDroppedPackets']
    if (status not in ('complete', 'unavailable') or
        (status == 'complete' and (type(dropped) is not int or not 0 <= dropped < 2**63)) or
        (status == 'unavailable' and dropped is not None)):
        raise ValueError('invalid_capture_statistics')
    if value['authenticatedFrames'] > value['clientFrames'] + value['serverFrames']:
        raise ValueError('invalid_quality_count')
    for key in ('containerComplete', 'transportComplete', 'sessionComplete'):
        if type(value[key]) is not bool:
            raise ValueError('invalid_quality_flag')
    if value['sessionComplete'] and (value['uncapturedConnections'] or value['sessionErrorCount'] or
                                     value['unsupportedConnections'] or dropped):
        raise ValueError('inconsistent_quality_claim')
    if value['terminationBasis'] not in ('process_exit', 'tcp_fin') or value['timeBasis'] != 'packet_completing_message':
        raise ValueError('invalid_quality_basis')
    from .capture_metadata import LOCALES
    if value['locale'] not in LOCALES or value['localeSource'] not in ('game_config', 'fallback', 'unknown'):
        raise ValueError('invalid_quality_locale')
    offset = value['utcOffsetSeconds']
    if offset is not None and (type(offset) is not int or abs(offset) > 50400 or offset % 60):
        raise ValueError('invalid_quality_offset')
    return value


def write_session_metadata(dumps, session, observation, context):
    """Write only after session-wide errors and missing connections are known.

    A sidecar failure never deletes or invalidates a successfully saved PKT.
    Missing sidecars mean unknown quality to downstream consumers.
    """
    dumps = safe_store(dumps)
    success = True
    for item in session['captures']:
        if not item.get('ok') or item.get('storage') != 'dumps':
            continue
        try:
            name = item['file']
            if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,180}\.pkt', name):
                raise ValueError('invalid_capture_name')
            value = receipt_data(item, session, observation, context)
            pkt = dumps / name
            if _regular(pkt).st_size != value['pktBytes'] or _hash(pkt) != value['pktSha256']:
                raise ValueError('capture_digest_mismatch')
            target = pkt.with_name(pkt.name + '.capture.json')
            data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')
            if target.exists() or target.is_symlink():
                if _regular(target).st_size != len(data) or target.read_bytes() != data:
                    raise ValueError('quality_receipt_collision')
            else:
                staging = safe_store(dumps.parent / 'private-exports')
                fd, temp = tempfile.mkstemp(prefix='receipt-', suffix='.tmp', dir=staging)
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(data); stream.flush(); os.fsync(stream.fileno())
                    os.link(temp, target)
                finally:
                    Path(temp).unlink(missing_ok=True)
            item['metadata_file'] = target.name
            item['metadata_saved'] = True
        except (OSError, ValueError, KeyError, TypeError):
            item['metadata_saved'] = False
            success = False
    session['quality_metadata_complete'] = success
