"""Automatic capture-time context for PKT metadata."""
from datetime import datetime
from pathlib import Path
import re
import time

LOCALES = frozenset(('enUS', 'enGB', 'deDE', 'esES', 'esMX', 'frFR', 'itIT',
                     'koKR', 'ptBR', 'ruRU', 'zhCN', 'zhTW'))


def validate_metadata(value):
    if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1:
        raise ValueError('invalid_capture_metadata')
    offset = value.get('utc_offset_seconds')
    if type(offset) is not int or not -14*3600 <= offset <= 14*3600 or offset % 60:
        raise ValueError('invalid_utc_offset')
    if type(value.get('locale')) is not str or value['locale'] not in LOCALES:
        raise ValueError('invalid_locale')
    return {'schema': 1, 'utc_offset_seconds': offset, 'locale': value['locale']}


def game_locale(wow):
    """Read only the textLocale setting; never retain the rest of Config.wtf."""
    try:
        with (Path(wow).parent/'WTF'/'Config.wtf').open('rb') as stream:
            raw = stream.read(1024*1024+1)
        if len(raw) <= 1024*1024:
            matches = re.findall(rb'^\s*SET\s+textLocale\s+"([a-z]{2}[A-Z]{2})"\s*$',
                                 raw.removeprefix(b'\xef\xbb\xbf'), re.MULTILINE)
            if matches and matches[-1].decode('ascii') in LOCALES:
                return matches[-1].decode('ascii'), 'game_config'
    except OSError:
        pass
    return 'enUS', 'fallback'


def capture_context(wow):
    """Snapshot the client's locale and host's UTC offset when WoW is detected."""
    locale, source = game_locale(wow)
    now = datetime.now().astimezone()
    value = {'schema': 1, 'utc_offset_seconds': int(now.utcoffset().total_seconds()),
             'locale': locale, 'locale_source': source,
             'recorded_at_unix_ns': time.time_ns(), 'offset_source': 'capture_host'}
    validate_metadata(value)
    return value
