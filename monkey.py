#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import argparse
import logging
import json
import socket
import uuid

from quasimodo.stubs import Ape, Monkey
from paho.mqtt.client import Client

from quasimodo_jwt.jwt_glue import parse_jwt_claim, create_jwt_claim
from quasimodo_jwt.jwt_glue import load_jwk

OPT_NO_VALUE = "<use implementation's default>"

pub_key = load_jwk('./test_pub.pem')
priv_key = load_jwk('./test_private.pem')

class DumpMixin(object):
    def _handle_request(self, payload, **kwargs):
        success = True

        self.log.warning("GOT {!r}".format(payload))
        try:
            parsed = parse_jwt_claim(payload, pub_key)
        except Exception as exc:
            parsed = None
            self.log.error(exc)
        self.log.info("PARSED {!r}".format(parsed))

        self.log_data_dump(parsed)

        return {
            "success": success
        }


class ApeDumper(DumpMixin, Ape):
    def simple_publish(self, payload, routing_key='', **kwargs):
        sp_client_id = 'spc-' + str(uuid.uuid4())
        sp_client = Client(client_id=sp_client_id, transport="websockets")
        sp_client.ws_set_options(self.endpoint)
        sp_client.username_pw_set(self.credentials[0], self.credentials[1])
        if self.tls_context:
            sp_client.tls_set_context(self.tls_context)
        sp_client.connect(self.host, self.port,
                          keepalive=self.heartbeat_interval)

        sp_client.loop_start()

        res = sp_client.publish(routing_key, payload=payload)
        res.wait_for_publish()

        sp_client.loop_stop()
        self.log.debug("rc={!r}".format(res.rc))
        return res.rc == 0

    def callback(self, client, userdata, message):
        try:
            payload = json.loads(message.payload)
        except Exception as exc:
            payload = message.payload

        self.handle_request(payload,
                            client=client, userdata=userdata, message=message)

class MonkeyDumper(DumpMixin, Monkey):
    def simple_publish(self, payload, routing_key='', **kwargs):
        return self.add_to_exchange(payload, routing_key=routing_key, content_type="text/plain", **kwargs)


def dump_hunchback_parameters(kwargs, connection_option_keys, use_log=None):
    if use_log is None:
        use_log = logging.getLogger(__name__)
    use_log.info("Parameters")
    use_log.info("=" * 80)
    all_option_keys = set(kwargs.keys())
    all_option_keys |= set([x[0] for x in connection_option_keys])
    base_class = None

    if kwargs.get("flavour") == 'amqp':
        base_class = Monkey
    elif kwargs.get("flavour") == 'mqtt':
        base_class = Ape

    for key in sorted(all_option_keys):
        implementation_attribute = 'DEFAULT_{:s}'.format(key).upper()

        try:
            fallback_val = getattr(base_class, implementation_attribute)
        except AttributeError:
            fallback_val = None

        val = kwargs.get(key, fallback_val)
        use_log.info("{key:14}: {val!r}".format(key=key, val=val))


def hunchback_client():
    parser = argparse.ArgumentParser()
    flavours = ('amqp', 'mqtt')
    connection_option_keys = (
        ('host', 'a'),
        ('port', 'i'),
        ('username', 'u'),
        ('password', 'p'),
    )

    parser.add_argument('-n', '--dry-run', action='store_true',
                        dest="dry_run",
                        default=False, help="Dry run mode")

    publishing_group = parser.add_argument_group("Publishing")
    publishing_group.add_argument(
        'payloads', metavar='DATA', nargs='*',
        help='Payloads - either JSON encoded parameter or path of a JSON '
             'encoded file')
    publishing_group.add_argument(
        '-r', '--routing-key', dest="routing_key",
        default='quasimodo.notifications',
        help="Topic")

    flavour_group = parser.add_argument_group("Protocol")
    group = flavour_group.add_mutually_exclusive_group()
    for flavour in flavours:
        group.add_argument('--{:s}'.format(flavour), const=flavour,
                           action="store_const",
                           dest="flavour",
                           default=flavours[0],
                           help="Use {!r} as protocol ".format(flavour))

    connection_group = parser.add_argument_group("Generic Connection Options")
    for opt_l, opt_s in connection_option_keys:
        env_key = 'QUASIMODO_{:s}'.format(opt_l).upper()
        connection_group.add_argument(
            '-{:s}'.format(opt_s), '--{:s}'.format(opt_l),
            dest=opt_l, default=os.environ.get(env_key, OPT_NO_VALUE),
            help="{!r} parameter. Default: %(default)s, "
                 "Environment variable: {!r}".format(opt_l, env_key))
    connection_group.add_argument(
        '--listen', dest="binding_keys", default=[],
        action="append",
        help="Subscriptions")
    connection_group.add_argument(
        '--no-tls', dest="tls", default=True, action="store_false",
        help="Disable TLS")

    amqp_group = parser.add_argument_group("AMQP Connection Options")
    amqp_group_queue = amqp_group.add_mutually_exclusive_group()
    env_key_queue = 'QUASIMODO_QUEUE'
    env_key_exchange = 'QUASIMODO_EXCHANGE'
    amqp_group_queue.add_argument(
        '--queue',
        dest="queue", default=os.environ.get(env_key_queue, False),
        help="Queue, Environment variable: {!r}".format(env_key_queue))
    amqp_group_queue.add_argument(
        '--exchange',
        dest="exchange", default=os.environ.get(env_key_exchange, 'amq.topic'),
        help="Exchange, Environment variable: {!r}".format(env_key_exchange))

    cli_args = parser.parse_args()
    kwargs = dict()

    for key, val in vars(cli_args).items():
        if val == OPT_NO_VALUE:
            continue
        elif key == "binding_keys" and not val:
            continue

        kwargs[key] = val

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y%m%d %H:%M:%S')
    logging.getLogger('pika').setLevel(logging.WARNING)

    log = logging.getLogger(__name__)
    log.debug(kwargs)

    if cli_args.flavour == 'amqp':
        impl = MonkeyDumper(**kwargs)
    elif cli_args.flavour == 'mqtt':
        impl = ApeDumper(**kwargs)
    else:
        raise ValueError(
            "Implementation for {!r} is not available!".format(
                cli_args.flavour))

    if cli_args.dry_run:
        log.info("DRY RUN.")
        log.info("")
        dump_hunchback_parameters(kwargs, connection_option_keys)
        sys.exit(0)

    payloads = []
    if cli_args.payloads:
        for p_in in cli_args.payloads:
            try:
                if os.path.isfile(p_in):
                    with open(p_in, "r") as src:
                        payload = json.load(src)
                else:
                    payload = json.loads(p_in)
                payloads.append(payload)
            except Exception as exc:
                log.info("Ignoring payload {!r}, GOT {!s}".format(p_in, exc))

        if not payloads:
            log.error("No payloads? No gain.")
            sys.exit(2)

    try:
        if payloads:
            for payload in payloads:
                jwt_payload = create_jwt_claim(priv_key, payload).decode('utf-8')
                impl.simple_publish(jwt_payload, cli_args.routing_key)
        else:
            impl.run()
    except socket.error as sexc:
        log.error("Could not connect: {!s}".format(sexc))
        dump_hunchback_parameters(kwargs, connection_option_keys)
        log.info("")
        log.info("Implementation Object:")
        log.info("=" * 80)
        log.info(impl)
        sys.exit(3)
    except KeyboardInterrupt:
        impl.log.info("You pressed Ctrl-C. This will be reported.")
        sys.exit(1)

    sys.exit(0)

if __name__ == '__main__':
    hunchback_client()
