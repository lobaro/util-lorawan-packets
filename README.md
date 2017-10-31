# util-lorawan-packets

A simple library just to pack (marshal) and parse (unmarshal) LoRaWAN packets in C. 
It's intended to be used as basis in upper-layer LoRaWAN node oder network-server stack implementations. 

## Features

- Stack independent LoRaWAN packet parser & encoder
- Easy integration into custom upper-layer LoRaWAN stack implementations
- Only 5 functions: Init, New, Delete, Marshal, Unmarshal
- [x] Support LoRaWAN 1.0 protocol
- [ ] Support LoRaWAN 1.1 protocol

The Following message types (MType) are implemented:
- JoinRequest 
- JoinAccept
- UnconfirmedDataUp
- UnconfirmedDataDown
- ConfirmedDataUp
- ConfirmedDataDown
- TBD: RejoinRequest (LoRaWAN 1.1)

# Background 

We use this library internally inside our proprietary closed-source (sorry!) freeRTOS based LoRaWAN-Stack. 
At Lobaro we heavily try to achieve a flexible & modular code-base to get projects done fast. With embedded C-code this is often not that easy as with modern languages like goLang. This might be the reason why most (if not all) C based LoRaWAN implementations mix the simple task of packet encode/decode with protocol business logic. 

This library tries to decouple the packet generation from LoRaWAN stack logic and include cleanly separated only the absolut minimum of needed LoRaWAN state like the keys or framecounters. We think that this LoRaWAN packet encode/decode library is valuable for anybody writing its own LoRaWAN stack. Writing a own LoRaWAN stack is not that hard but crucial for getting the most out of the protocol.

# Future development

Soon the support of the LoRaWAN 1.1 specification should be integrated. 

Additions / Fixes will be constantly merged into this repository. 

# Demo/Example

... TBD ...

# Related

- This lib is partly based on the work of [JiapengLi, LoRaWAN protocol parser and packer in C](https://github.com/JiapengLi/lorawan-parser). 
- Follow [Lobaro on Twitter](https://twitter.com/LobaroHH) to get latest news about our iot projects.

# Contribute
We appreciate any feedback, do not hesitate to create issues or pull requests.

