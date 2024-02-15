from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.io import PrintWriter
from java.text import SimpleDateFormat
from java.util import Date, TimeZone


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Timestamp Generator System")
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        callbacks.printOutput(".::Timestamp Generator::.")
        callbacks.printOutput("Author: Old Joker")
        callbacks.printOutput("Version: 1.0")
        callbacks.printOutput(
            """Description:
            This Burp Suite extension automates the generation of timestamps, facilitating seamless integration with the Intruder Tools.
            It enables the effortless insertion of timestamps into payloads, enhancing the efficiency of various security testing activities."""
        )
        callbacks.printOutput("GitHub: https://github.com/old-joker/TimestampGenerator")

        return

    def getGeneratorName(self):
        return "Timestamp Generator System"

    def createNewInstance(self, attack):
        return EpochTime(self, attack)


class EpochTime(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.timezone = TimeZone.getDefault()
        return

    def hasMorePayloads(self):
        return True

    def getNextPayload(self, current_payload):
        dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
        dateFormat.setTimeZone(self.timezone)
        timestampStr = dateFormat.format(Date())
        return timestampStr.encode()

    def reset(self):
        return
