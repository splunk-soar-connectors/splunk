**Unreleased**

* Enabled TLS certificate verification by default for new Splunk assets.
* Escaped event identifiers before using them in Splunk searches during notable event updates.
* Preferred Enterprise Security urgency when assigning severity to polled notable events.
* Disabled XML entity processing explicitly when parsing Splunk server responses.
* Bounded each Splunk search job to the configured total job timeout.
