import xml.etree.ElementTree as ET
import asyncio, time, configparser, os, argparse, pathlib

CONCURRENT = 5
CONFIG_LOCATION = "config.ini"
SCAN_LOCATION = "out.xml"
OUTPUT_LOCATION = "/tmp/output"

class Filter:

    def __init__(self, section):
        self.protos = self.clean(section["proto"]) if "proto" in section else None
        self.ports = self.clean(section["ports"]) if "ports" in section else None
        self.services = self.clean(section["services"]) if "services" in section else None

    def clean(self, string):
        return [e.strip() for e in string.split(",")]


class Host:

    def __init__(self, ip, ports=None, task=False):
        self.ip = ip
        self.ports = ports if ports is not None and type(ports) is list and len(ports) > 0 else None
        self.task = task

        self.process = None

        self.start = None
        self.elapsed = None

        self.lastInput = None

        self.failed = False

    def formatCommand(self, cmd):
        args = cmd.count("{}")

        if args > 2 or args <= 0:
            raise Exception("error parsing command")

        if args == 1:
            return cmd.format(self.ip)
        elif args == 2:
            if self.ports:
                return cmd.format(self.ip, ",".join(self.ports))
            else:
                return False

    def __eq__(self, other):
        if not isinstance(other, Host):
            return False
        return self.ip == other.ip

    def __str__(self):
        return "{} {} {}".format(self.ip, str(self.ports) if self.ports else "", str(self.task) if self.task else "").strip()

    def __repr__(self):
        return str(self)


def parseXml(filter, location):
    tree = ET.parse(location)
    root = tree.getroot()

    hosts = root.findall('host')

    hostdata = []

    for host in hosts:
        if not host.findall('status')[0].attrib['state'] == 'up':
            continue

        ip = host.findall('address')[0].attrib['addr']
        hostname = host.findall('hostnames')

        portdata = []

        if filter.ports or filter.services:

            port_element = host.findall('ports')
            ports = port_element[0].findall('port')

            for port in ports:
                if not 'open' in port.findall('state')[0].attrib['state']:
                    continue
                
                if (port.attrib['protocol'] in filter.protos 
                    and (
                        (port.attrib['portid'] in [str(p) for p in filter.ports] if filter.ports else False)
                        or (any(
                            [service == port.findall('service')[0].attrib['name'] 
                            for service in filter.services]
                            ) if filter.services is not None else False)
                        )
                    ):
                    portdata.append(port.attrib['portid'])

        hostdata.append(Host(ip, portdata))

    return hostdata


async def runCommand(host, semaphore, command):
    async with semaphore:
        print(command)

        host.start = time.time()
        host.process = await asyncio.create_subprocess_shell(command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

        lines = await host.process.communicate()

        await host.process.wait()

        if host.process.returncode == 0:
            pathlib.Path(OUTPUT_LOCATION + "/{}".format(host.ip)).mkdir(parents=True, exist_ok=True)

            with open(OUTPUT_LOCATION + "/{}/{}.txt".format(host.ip, command.split(" ")[0]), "w") as output:
                output.write("".join([line.decode() for line in lines]))

        host.elapsed = time.time() - host.start

        return host, bool(host.process.returncode)


async def heartbeat(hosts):
    while True:
        await asyncio.sleep(20)
        print("{} task(s) remaining".format(len([host.task for host in hosts if host.task])))

        for host in hosts:
            # send enter every minute on long running tasks in case they expect input
            if host.task and host.start and (time.time() - host.start) > 120 and (not host.lastInput or (time.time() - host.lastInput) > 60):
                try:
                    print("sending enter")
                    host.process.stdin.write(b'\n')
                    await host.process.stdin.drain()
                    host.lastInput = time.time()
                except ConnectionResetError:
                    continue


async def startScan(hosts, cmd):
    semaphore = asyncio.Semaphore(CONCURRENT)
    pending = []

    beat = asyncio.get_event_loop().create_task(heartbeat(hosts))

    for host in hosts:
        try:
            command = host.formatCommand(cmd)

            if command:
                pending.append(asyncio.ensure_future(runCommand(host, semaphore, command)))
                host.task = True

        except Exception as e:
            print(e)
            asyncio.get_event_loop().stop()

    while True:
        if not pending:
            beat.cancel()
            break

        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

        for task in done:
            result, error = task.result()

            try:
                host = next(host for host in hosts if host == result)
                host.task = False
                if error:
                    host.failed = True

                print("task on host {} done, took {}".format(host.ip, time.strftime("%H:%M:%S",time.gmtime(host.elapsed))))
            
            except Exception:
                print("something went wrong, shutting down...")
                asyncio.get_event_loop().stop()


async def main(tool):
    if os.path.exists(SCAN_LOCATION) and os.path.exists(CONFIG_LOCATION):

        config = configparser.ConfigParser()
        config.read(CONFIG_LOCATION)

        if tool in config.sections():
            try:
                section = config[tool]

                hosts = parseXml(Filter(section), SCAN_LOCATION)

                print(hosts)

                command = config[tool]["command"]

            except KeyError:
                return "error parsing config"

        else:
            return "no config for tool"
        
        await startScan(hosts, command)
        return f"{len([host for host in hosts if host.failed])} task(s) failed"

    else:
        return "required files not found"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="parse nmap file and run tool based on output")
    parser.add_argument("tool", nargs="+", help='tool to run from config.ini')

    args = parser.parse_args()

    try:
        result = asyncio.get_event_loop().run_until_complete(main(args.tool[0]))
        print(result)

    except (KeyboardInterrupt, SystemExit):
        print("stopping...")
        asyncio.get_event_loop().stop()
        
