import asyncio
import os
from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer


async def main():
    from main import make_ice_servers_credentials
    iceServers = make_ice_servers_credentials()

    iceServers = iceServers[1:]
    for i in range(len(iceServers)):
        url = iceServers[i]['urls']

        pc = RTCPeerConnection(configuration={
            "iceServers": [RTCIceServer(
                urls=url,
                username=iceServers[i]['username'],
                credential=iceServers[i]['credential'],
            )],
        })

        config = RTCConfiguration(
            iceServers=[RTCIceServer(
                urls=url,
                username=iceServers[i]['username'],
                credential=iceServers[i]['credential'],
            )],
        )
        pc = RTCPeerConnection(configuration=config)

        # To run ICE, data channel is enough
        pc.createDataChannel("probe")

        # Collect candidates
        @pc.on("icecandidate")
        def on_icecandidate(event):
            if event.candidate:
                print("CANDIDATE:", event.candidate.to_sdp().strip())

        # Gathering completion marker
        gathering_done = asyncio.get_event_loop().create_future()

        @pc.on("icegatheringstatechange")
        def on_state_change():
            if pc.iceGatheringState == "complete" and not gathering_done.done():
                gathering_done.set_result(True)

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)

        # Wait for ICE gathering completion (timeout just in case)
        try:
            await asyncio.wait_for(gathering_done, timeout=10)
        except asyncio.TimeoutError:
            pass

        has_relay = any(" typ relay " in line for line in (pc.localDescription.sdp or "").splitlines())

        await pc.close()

        if has_relay:
            print(f"\n{url} = ✅ TURN OK")
        else:
            print(f"\n{url} = ❌ TURN FAIL")


if __name__ == "__main__":
    asyncio.run(main())
