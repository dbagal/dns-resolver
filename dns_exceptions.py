
class ResolutionError(Exception):
    def __init__(self, zone_name, nameservers):
        msg = f"""
        Cannot find Resource Records for {zone_name} in any of the following nameservers: 
        {nameservers}
        """
        super().__init__(msg)


class ResourceRecordTypeError(Exception):
    def __init__(self, type):
        msg = f"{type} is not a valid resource record type"
        super().__init__(msg)


class KSKVerificationError(Exception):
    def __init__(self, zone_name):
        msg = f"KSK verification for '{zone_name}' failed."
        super().__init__(msg)


class ZSKVerificationError(Exception):
    def __init__(self, zone_name):
        msg = f"ZSK verification for '{zone_name}' failed."
        super().__init__(msg)


class RRSetVerificationError(Exception):
    def __init__(self, zone_name):
        msg = f"RRSet verification for '{zone_name}' failed."
        super().__init__(msg)


class NoDNSSECSupportError(Exception):
    def __init__(self, zone_name):
        msg = f"DNSSEC not enabled for '{zone_name}'"
        super().__init__(msg)
