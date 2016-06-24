missing_gw = object()


def cfg_build_proxies(cfg, *section_names):
    from . import chain

    result = []
    for name in section_names:
        section = cfg.get_section(name)

        result.append((
            chain.Proxies.from_cfg_string(section.get_str('Прокси')),
            cfg_get_gateway(cfg, name),
        ))

    return result


def cfg_get_gateway(cfg, section_name):
    default_gateway = cfg.get_str('Шлюз')
    gateway = cfg.get_section(section_name).get_str('Шлюз', default=missing_gw)

    if gateway == 'Нет':
        gateway = None
    elif gateway is missing_gw:
        gateway = default_gateway

    return gateway
