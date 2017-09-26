"""Main module"""
import concurrent.futures
import time
import requests


def chunks(l, n):
    """Yield successive n-sized chunks from l. (https://stackoverflow.com/a/312464/157880)"""
    for i in range(0, len(l), n):
        yield l[i:i + n]


class VirusTotal:
    """Main class"""

    def __init__(self, configfile):
        import configparser
        import os
        config = configparser.ConfigParser()
        config.read(configfile)
        self.apikey = config["VIRUSTOTAL"]["apikey"]
        self.num_async_workers = config["client"].get("num_workers", "0")
        if not int(self.num_async_workers):
            # We're i/o bound. Let's load this up.
            self.num_async_workers = os.cpu_count() * 5
        else:
            self.num_async_workers = int(self.num_async_workers)

        self.filereportapi = "https://www.virustotal.com/vtapi/v2/file/report"

    def batch_get_report(self, hashlist, allinfo=False):
        hashes = ",".join(hashlist)
        params = {'apikey': self.apikey, 'resource': hashes}
        if allinfo:
            params['allinfo'] = 1
        for retry in range(5):
            response = requests.get(self.filereportapi, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                sys.stderr.write(hashes + "\n")
                sys.stderr.write(str(response.status_code) + '\n')
                time.sleep(1)

    def batch_get_report_async(self, hashlist, allinfo=False):
        finaldata = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_async_workers) as executor:
            future_to_list = {executor.submit(
                self.batch_get_report, chunk, allinfo): chunk for chunk in chunks(hashlist, 25)}
            for future in concurrent.futures.as_completed(future_to_list):
                hashsublist = future_to_list[future]
                try:
                    finaldata += future.result()
                except Exception as exc:
                    print('%r generated an exception: %s' % (md5sublist, exc))
                else:
                    print('GOOD')
        return finaldata


if __name__ == "__main__":
    import sys
    vt = VirusTotal(sys.argv[1])
    finaldata = []

    print(vt.batch_get_report_async(
        ['411475F231585EEF5C8F00055F422FB1', 'F5BA2982D2BD2241E4A4AB24B37514D8']))
