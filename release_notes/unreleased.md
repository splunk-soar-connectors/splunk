**Unreleased**

* Corrected Splunk CIM field mappings to emit canonical CEF keys for bytes, translated destination addresses, and source users.

* Preserved Splunk HTTP error responses through proxied SDK connections so authentication and server errors retain their normal handling.

* Applied the connector request timeout to proxied Splunk SDK connections so stalled endpoints no longer wait indefinitely.
