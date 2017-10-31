# util-lorawan-packets

A simple library just to pack (marshal) and parse (unmarshal) LoRaWAN packets in C. 
It's intended to be used as basis for upper-layer LoRaWAN node oder network-server stacks. Beside this it could be useful for LoRaWAN testing and verification purposes.

When using this library knowledge about the LoRaWAN specification is needed. You can request the LoRaWAN specification here: https://www.lora-alliance.org/for-developers

# Features

- Stack independent LoRaWAN packet parser & encoder
- Easy integration into custom upper-layer LoRaWAN stack implementations
- Only 5 functions: Init, New, Delete, Marshal, Unmarshal
- [x] Support LoRaWAN 1.0 protocol (EU868 only)
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
At Lobaro we heavily try to achieve a flexible & modular code-base to get projects done fast. With embedded C-code this is often not that easy as with modern languages like goLang. This might be the reason why most LoRaWAN implementations mix the "simple" task of packet encode/decode with protocol business logic. 

This library tries to decouple the packet generation from LoRaWAN stack logic. It includes - cleanly separated - only the absolute minimum of needed LoRaWAN state like keys or framecounters. We think that this LoRaWAN packet encode/decode library is valuable for anybody writing its own LoRaWAN stack. Writing an own LoRaWAN stack is not that hard and can be crucial for getting the most out of the protocol for a particular application.

## Future development

+ Additions / Fixes will be constantly merged into this repository. 
+ Soon the support of the LoRaWAN 1.1 specification should be integrated.
+ Add GoLang cgo wrapper

## Demo/Example

TBD 

## Related

- This lib is partly based on the work of [JiapengLi](https://github.com/JiapengLi/lorawan-parser) and his command line tool for LoRaWAN packet parsing & encoding
- Similar approach for GoLang https://github.com/brocaar/lorawan.
- Follow [Lobaro on Twitter](https://twitter.com/LobaroHH) to get latest news about our iot projects.

## Contribute

We appreciate any feedback, do not hesitate to create issues or pull requests.

## License

util-lorawan-packets is licensed under [The MIT License](http://opensource.org/licenses/mit-license.php). Check LICENSE for more information.

AES, CMAC have its own licenses. Please follow links below to get the details.

## Acknowledgement

+ LoRa Alliance https://www.lora-alliance.org/
+ Brian Gladman. AES library http://www.gladman.me.uk/
+ Lander Casado, Philippas Tsigas. CMAC library http://www.cse.chalmers.se/research/group/dcs/masters/contikisec/
+ JiapengLi, LoRaWAN protocol parser and packer in C https://github.com/JiapengLi/lorawan-parser
