package examples

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ably/ably-go/ably"
)

func InitRealtimeClient() *ably.Realtime {
	client, err := ably.NewRealtime(
		ably.WithKey(os.Getenv(AblyKey)),
		// ably.WithEchoMessages(true), // Uncomment to stop messages you send from being sent back
		ably.WithClientID(UserName))
	if err != nil {
		panic(err)
	}
	return client
}

func RealtimeSubscribeToEvent(client *ably.Realtime) func() {
	channel := client.Channels.Get(ChannelName)

	// Subscribe to messages sent on the channel
	unsubscribe, err := channel.Subscribe(context.Background(), EventName, func(msg *ably.Message) {
		fmt.Printf("Received message from %v: '%v'\n", msg.ClientID, msg.Data)
	})
	if err != nil {
		err := fmt.Errorf("error subscribing to channel: %w", err)
		fmt.Println(err)
	}
	return unsubscribe
}

func RealtimeEnterPresence(client *ably.Realtime) {
	channel := client.Channels.Get(ChannelName)
	pErr := channel.Presence.Enter(context.Background(), UserName+" entered the channel")
	if pErr != nil {
		err := fmt.Errorf("error with enter presence on the channel %w", pErr)
		fmt.Println(err)
	}
}

func RealtimeLeavePresence(client *ably.Realtime) {
	channel := client.Channels.Get(ChannelName)
	pErr := channel.Presence.Leave(context.Background(), UserName+" entered the channel")
	if pErr != nil {
		err := fmt.Errorf("error with leave presence on the channel %w", pErr)
		fmt.Println(err)
	}
}

func RealtimePublish(client *ably.Realtime, message string) {
	channel := client.Channels.Get(ChannelName)
	// Publish the message typed in to the Ably Channel
	err := channel.Publish(context.Background(), EventName, message)
	if err != nil {
		err := fmt.Errorf("error publishing to channel: %w", err)
		fmt.Println(err)
	}
}

func Jsonify(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
