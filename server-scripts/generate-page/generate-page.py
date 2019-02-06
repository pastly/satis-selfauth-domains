#!/usr/bin/env python3
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from configparser import ConfigParser
import logging
import os


DEFAULT_CONFIG = 'config.default.ini'
logging.basicConfig(format='%(asctime)s %(levelname)s %(threadName)s '
                    '%(filename)s:%(lineno)s - %(funcName)s - %(message)s',
                    level=logging.DEBUG)
log = logging.getLogger(__name__)

LIST_ID = 'sat_domain_list'
LIST_ITEM_FROM_CLASS = 'sat_domain_from'
LIST_ITEM_TO_CLASS = 'sat_domain_to'

START_HTML = '''
<ul id="%s">
''' % LIST_ID

ITEM_HTML = '''
<li class='sat_domain_list_item'>
    <a href='https://{sat_name}'><span class="%s">{sat_name}</span></a>
    is a valid SAT domain for
    <a href='https://{trad_name}'><span class="%s">{trad_name}</span></a>
</li>
''' % (LIST_ITEM_FROM_CLASS, LIST_ITEM_TO_CLASS)

END_HTML = '''
</ul> <!-- sat_domain_list -->
'''


def parse_domain_list_fd(fd):
    out = {}
    for line in fd:
        line = line.strip()
        if not len(line) or line[0] == '#':
            continue
        names = line.split()
        if len(names) != 2:
            log.warning('Ignoring malformed line: %s', line)
            continue
        selfauth_name, trad_name = names
        if not selfauth_name.endswith(trad_name):
            log.warning(
                'Ignoring line "%s": selfauth name must end with traditional '
                'name', line)
            continue
        if trad_name not in out:
            out[trad_name] = set()
        log.debug(
            'Adding %s as selfauth name for %s',
            selfauth_name, trad_name)
        out[trad_name].add(selfauth_name)
    num_trad = len(out)
    num_selfauth = len(set().union(*[out[n] for n in out]))
    log.info(
        'Loaded %s selfauth names for %d traditional names',
        num_selfauth, num_trad)
    return out


def get_config(args):
    c = ConfigParser()
    for fname in [DEFAULT_CONFIG, args.config]:
        if os.path.isfile(fname):
            log.debug('Reading config file %s', fname)
            c.read_file(open(fname, 'rt'), source=fname)
    return c


def output_html(fd, pre_text, post_text, mapping):
    fd.write(pre_text)
    fd.write(START_HTML)
    for trad_name in mapping:
        for selfauth_name in mapping[trad_name]:
            fd.write(
                ITEM_HTML.format(sat_name=selfauth_name, trad_name=trad_name))
    fd.write(END_HTML)
    fd.write(post_text)


def main(args, conf):
    domain_list_fname = conf.get('paths', 'sat_domain_list_fname')
    if not os.path.isfile(domain_list_fname):
        log.error('Configured domain list %s must exist', domain_list_fname)
        return 1
    mapping = parse_domain_list_fd(open(domain_list_fname, 'rt'))
    pre_fname = conf.get('paths', 'pre_html_fname')
    post_fname = conf.get('paths', 'post_html_fname')
    pre_text = open(pre_fname, 'rt').read() \
        if os.path.isfile(pre_fname) else ''
    post_text = open(post_fname, 'rt').read() \
        if os.path.isfile(post_fname) else ''
    output_html(open(args.output, 'wt'), pre_text, post_text, mapping)
    return 0


if __name__ == '__main__':
    p = ArgumentParser(
            formatter_class=ArgumentDefaultsHelpFormatter)
    p.add_argument('-c', '--config', type=str, default='config.ini')
    p.add_argument('-o', '--output', type=str, default='/dev/stdout')
    args = p.parse_args()
    conf = get_config(args)
    exit(main(args, conf))
