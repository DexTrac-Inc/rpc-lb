#!/usr/bin/python3

import json
import requests
import sys
from web3 import Web3
from web3.middleware import geth_poa_middleware

class BlockChecker:
    def __init__(self, node_ip, node_port):
        self.node_ip = node_ip
        self.node_port = node_port
        self.load_network_data()

    def load_network_data(self):
        with open('/var/lib/haproxy/networks.json', 'r') as networks_file:
            network_data = json.dumps(json.loads(networks_file.read()), sort_keys=True)
        self.networks = json.loads(network_data)['networks']
        self.nodes = json.loads(network_data)['nodes']

    def get_explorer_block(self, network, url, api_key):
        session = requests.Session()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        if network == 'metis':
            api_url = f"{url}?module=block&action=eth_block_number"
        else:
            api_url = f"{url}?action=eth_blockNumber&module=proxy&apikey={api_key}"
        try:
            response = session.get(api_url, headers=headers, timeout=3)
        except Exception:
            pass
        else:
            if response.status_code == 200 and 'result' in response.json():
                block_number = response.json()['result']
                return int(block_number, 16)
        return int('0x0', 16)

    def get_rpc_block(self, network, url):
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': 3}))
        if w3.is_connected() == True:
            if not network == 'ethereum':
                w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            try:
                latest = w3.eth.get_block('latest')
            except Exception as error:
                pass
            else:
                if 'number' in latest:
                    return latest['number']
        raise Exception

    def get_node_block(self, ip, port):
        node_info = self.nodes[ip]

        if port == node_info['wsPort']:
            if ip.startswith('10.10.100'):
                url = f"ws://{ip}:{port}{node_info['wsAddtlUrl']}"
            else:
                url = f"wss://{node_info['dns']}:{port}{node_info['wsAddtlUrl']}"
            w3 = Web3(Web3.WebsocketProvider(url, websocket_timeout=3))
        elif port == node_info['httpPort']:
            if ip.startswith('10.10.100'):
                url = f"http://{ip}:{port}{node_info['httpAddtlUrl']}"
            else:
                url = f"https://{node_info['dns']}:{port}{node_info['httpAddtlUrl']}"
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': 3}))

        if w3.is_connected() == True:
            if not node_info['network'] == 'ethereum':
                w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            latest = w3.eth.get_block('latest')
            if 'number' in latest:
                return int(latest['number'])
        raise Exception

    def block_check(self, explorer_block, node_block):
        if (node_block > explorer_block) or abs(explorer_block - node_block) <= 10:
            return True
        return False

    def run_check(self):
        if self.node_ip in self.nodes:
            try:
                external_block_type = "primary rpc"
                external_block = self.get_rpc_block(
                    self.nodes[self.node_ip]['network'],
                    self.networks[self.nodes[self.node_ip]['network']]['rpc']['primary'],
                    )
            except Exception:
                try:
                    external_block_type = "secondary rpc"
                    external_block = self.get_rpc_block(
                    self.nodes[self.node_ip]['network'],
                    self.networks[self.nodes[self.node_ip]['network']]['rpc']['secondary'],
                    )
                except Exception:
                    try:
                        external_block_type = "explorer"
                        external_block = self.get_explorer_block(
                            self.nodes[self.node_ip]['network'],
                            self.networks[self.nodes[self.node_ip]['network']]['explorer']['api'],
                            self.networks[self.nodes[self.node_ip]['network']]['explorer']['apiKey']
                            )
                    except Exception:
                        external_block = int('0x0', 16)

            try:
                node_block = self.get_node_block(
                    self.node_ip,
                    self.node_port
                    )
            except Exception as error:
                exit(1)

            print({
                "network": self.nodes[self.node_ip]['network'],
                "nodeName": self.nodes[self.node_ip]['name'],
                "nodeIP": self.node_ip,
                "nodePort": self.node_port,
                "externalBlockType": external_block_type,
                "externalBlock": external_block,
                "nodeBlock": node_block
            })

            if self.block_check(external_block, node_block) == True:
                exit(0)
            else:
                exit(1)

        else:
            print(f"{{'nodeIP': {self.node_ip}, 'error': 'unknown node'}}")
            exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Error: Not enough arguments.")
        sys.exit(1)
    
    block_checker = BlockChecker(sys.argv[3], sys.argv[4])
    block_checker.run_check()
