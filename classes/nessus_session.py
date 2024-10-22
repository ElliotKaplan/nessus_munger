import requests

class NessusSession(requests.Session):
    def __init__(self, host, accessKey, secretKey, port):
        requests.Session.__init__(self)
        self.verify = False
        self.headers['X-ApiKeys'] = 'accessKey={}; secretKey={}'.format(
            accessKey, secretKey
        )
        self.host = host
        self.port = port
        self.root = 'https://{}:{}/'.format(host, port)

    def request(self, method, url, **kwargs):
        url = self.root + url
        return requests.Session.request(self, method, url, **kwargs)

class NessusScanSession(NessusSession):
    def __init__(self, scan_number, *args, history_id=None, **kwargs):
        NessusSession.__init__(self, *args, **kwargs)
        self.scan_number = scan_number
        self.root += 'scans/{}'.format(self.scan_number)
        self.base_query = {'history_id': history_id}

    def scan_name(self):
        resp = self.get('')
        data = resp.json()
        return data['info']['name']
