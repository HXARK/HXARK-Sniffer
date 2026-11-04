"""Client fingerprints, session layouts and validated build profiles."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionLayout:
    root_rva: int
    vtable_rva: int
    session_offset: int = 0x48
    slots_offset: int = 0x231
    slot_stride: int = 0x148
    slot_count: int = 4


DEFAULT_LAYOUT=SessionLayout(0x4a50750,0x40f8d00)


@dataclass(frozen=True)
class BuildProfile:
    build: int
    version: str
    image_sha256: str | None
    compressed_opcode: int
    bundle_opcode: int
    evidence: str
    live_verified: bool = False
    key_locator_verified: bool = False
    control_opcodes_verified: bool = False
    layout: SessionLayout | None = None


# 69875 control opcodes: static analysis only.
# 70575: complete continued-session capture validated on 2026-10-24.
# 70688: session layout, control opcodes and a complete authenticated connection
# validated locally on 2026-10-31. The 70575 profile remains independent.
# 70783: session layout, control opcodes and three complete authenticated
# connections validated locally on 2026-11-04.
PROFILES = {
    69875: BuildProfile(69875, '12.1.0.69875', None, 0x4c000e, 0x4c000d,
                        'reference_static_69875'),
    70575: BuildProfile(70575, '12.1.5.70575',
                        '14b70997cf6c7971a4fcd533b7f421316b6a3da0c8da3710425a8dd20e356a29',
                        0x4c000e, 0x4c000d, 'live_70575_continued_session_20261024',
                        live_verified=True, key_locator_verified=True, control_opcodes_verified=True,
                        layout=DEFAULT_LAYOUT),
    70688: BuildProfile(70688, '12.1.5.70688',
                        '5cc7dd578e4100f43b630eff8f8ae6fa32907cda83451c434ae01046052d1d4f',
                        0x4c000e, 0x4c000d, 'live_70688_continued_session_20261031',
                        live_verified=True, key_locator_verified=True, control_opcodes_verified=True,
                        layout=SessionLayout(0x4ae07d0,0x4187e88)),
    70783: BuildProfile(70783, '12.1.5.70783',
                        '01622a961b5ef41f7a8da63f3683a49b41ea27bb0f1ff8e737fc520fe75873dc',
                        0x4c000e, 0x4c000d, 'live_70783_authenticated_sessions_20261104',
                        live_verified=True, key_locator_verified=True, control_opcodes_verified=True,
                        layout=SessionLayout(0x4a51818,0x40f9ac8)),
}


def active_profiles():
    from .updates import installed,default_store
    from .trust import PUBLIC_KEY
    profiles=dict(PROFILES)
    for value in installed(default_store(),PUBLIC_KEY):
        layout=SessionLayout(**{k:value[k] for k in ('root_rva','vtable_rva','session_offset','slots_offset','slot_stride','slot_count')})
        profiles[value['build']]=BuildProfile(value['build'],value['version'],value['image_sha256'],
            value['compressed_opcode'],value['bundle_opcode'],'signed_continued_session_profile',True,True,True,layout)
    return profiles


def select_profile(build, *, experimental=False, image_sha256=None):
    profiles=active_profiles()
    if type(build) is not int or build not in profiles:
        raise ValueError('unsupported_build')
    if type(experimental) is not bool:
        raise ValueError('invalid_experimental_flag')
    profile=profiles[build]
    if not profile.live_verified and not experimental:
        raise ValueError('build_requires_validation')
    if image_sha256 is not None and image_sha256 != profile.image_sha256:
        raise ValueError('client_fingerprint_mismatch')
    return profile
