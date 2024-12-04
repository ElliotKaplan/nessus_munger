import sys
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

class NessusFolderSession(NessusSession):
    def __init__(self, folder_number, *args, **kwargs):
        NessusSession.__init__(self, *args, **kwargs)
        self.folder_number = folder_number
        # get the numbers and names of all the scans in the folder
        resp = self.get('scans', params={'folder_id': self.folder_number})
        scans = resp.json()['scans']
        # sort the scans by scan id
        scans.sort(key=lambda d: d['id'])
        # create lists for each scan in the folder
        self.scan_ids = [(s['id'], s['name']) for s in scans]
        self.scans = [NessusScanSession(s['id'], *args, **kwargs) for s in scans]
        

        
    
