Infos
-----

The idea of SMSListener is using python-gammu, be able to know when a sms is received. This script reflect the behavior of my phone which can vary from another one. So all the script is made to work with my phone and it can need changes to work with another. For instance the field "UnRead" of GetSMSStatus is always 0 even though I have unread messages on my phone. To  divert it I count the number of messages and when it is incremented it means that a message has been received.

I made two ways to get the number of messages one based on GetSMS and the other on GetNextSMS. They should both work but depending on the phone one could more efficient than the other. It can be tricky the understand them because for instance getLastMessage2 use GetNextSMS but the number returned after the loop is higher than the real number of messages and we should loop back downward to find the real last message.

