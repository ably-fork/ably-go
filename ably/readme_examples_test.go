// Generated by test_readme_examples. DO NOT EDIT
package ably_test

import "testing"
import "github.com/ably/ably-go/ably"
import "github.com/ably/ably-go/ably/ablytest"

/* README.md:15 */ import "context"

/* README.md:16 */ import "errors"

func TestReadmeExamples(t *testing.T) {
	t.Parallel()

	fmt := struct {
		Println func(a ...interface{}) (n int, err error)
		Printf  func(s string, a ...interface{}) (n int, err error)
	}{
		Println: func(a ...interface{}) (n int, err error) { return 0, nil },
		Printf:  func(s string, a ...interface{}) (n int, err error) { return 0, nil },
	}

	app := ablytest.MustSandbox(nil)
	defer safeclose(t, app)
	/* README.md:19 */ ctx := context.Background()
	/* README.md:23 */ client, err := ably.NewRealtime(ably.WithKey(app.Key()), ably.WithEnvironment(app.Environment), ably.WithUseBinaryProtocol(!ablytest.NoBinaryProtocol), ably.WithClientID("clientID"))
	/* README.md:24 */ if err != nil {
		/* README.md:25 */ panic(err)
		/* README.md:26 */
	}
	/* README.md:28 */ channel := client.Channels.Get("test")
	/* README.md:32 */ client.Close()
	/* README.md:40 */ client, err = ably.NewRealtime(
		/* README.md:41 */ ably.WithKey(app.Key()), ably.WithEnvironment(app.Environment), ably.WithUseBinaryProtocol(!ablytest.NoBinaryProtocol), ably.WithClientID("clientID"),
		/* README.md:42 */ ably.WithAutoConnect(false), // Set this option to avoid missing state changes.
		/* README.md:43 */)
	/* README.md:44 */ if err != nil {
		/* README.md:45 */ panic(err)
		/* README.md:46 */
	}
	/* README.md:48 */ // Set up connection events handler.
	/* README.md:49 */
	client.Connection.OnAll(func(change ably.ConnectionStateChange) {
		/* README.md:50 */ fmt.Printf("Connection event: %s state=%s reason=%s", change.Event, change.Current, change.Reason)
		/* README.md:51 */
	})
	/* README.md:53 */ // Then connect.
	/* README.md:54 */
	client.Connect()
	/* README.md:56 */ channel = client.Channels.Get("test")
	/* README.md:58 */ channel.OnAll(func(change ably.ChannelStateChange) {
		/* README.md:59 */ fmt.Printf("Channel event event: %s channel=%s state=%s reason=%s", channel.Name, change.Event, change.Current, change.Reason)
		/* README.md:60 */
	})
	/* README.md:66 */ unsubscribe, err := channel.SubscribeAll(ctx, func(msg *ably.Message) {
		/* README.md:67 */ fmt.Printf("Received message: name=%s data=%v\n", msg.Name, msg.Data)
		/* README.md:68 */
	})
	/* README.md:69 */ if err != nil {
		/* README.md:70 */ panic(err)
		/* README.md:71 */
	}
	/* README.md:75 */ unsubscribe()
	/* README.md:81 */ unsubscribe1, err := channel.Subscribe(ctx, "EventName1", func(msg *ably.Message) {
		/* README.md:82 */ fmt.Printf("Received message: name=%s data=%v\n", msg.Name, msg.Data)
		/* README.md:83 */
	})
	/* README.md:84 */ if err != nil {
		/* README.md:85 */ panic(err)
		/* README.md:86 */
	}
	/* README.md:88 */ unsubscribe2, err := channel.Subscribe(ctx, "EventName2", func(msg *ably.Message) {
		/* README.md:89 */ fmt.Printf("Received message: name=%s data=%v\n", msg.Name, msg.Data)
		/* README.md:90 */
	})
	/* README.md:91 */ if err != nil {
		/* README.md:92 */ panic(err)
		/* README.md:93 */
	}
	/* README.md:97 */ unsubscribe1()
	/* README.md:98 */ unsubscribe2()
	/* README.md:104 */ err = channel.Publish(ctx, "EventName1", "EventData1")
	/* README.md:105 */ if err != nil {
		/* README.md:106 */ panic(err)
		/* README.md:107 */
	}
	/* README.md:117 */ badClient, err := ably.NewRealtime(ably.WithKey("invalid:key"), ably.WithEnvironment(app.Environment), ably.WithUseBinaryProtocol(!ablytest.NoBinaryProtocol), ably.WithClientID("clientID"))
	/* README.md:118 */ if err != nil {
		/* README.md:119 */ panic(err)
		/* README.md:120 */
	}
	/* README.md:122 */ err = badClient.Channels.Get("test").Publish(ctx, "event", "data")
	/* README.md:123 */ if errInfo := (*ably.ErrorInfo)(nil); errors.As(err, &errInfo) {
		/* README.md:124 */ fmt.Printf("Error publishing message: code=%v status=%v cause=%v", errInfo.Code, errInfo.StatusCode, errInfo.Cause)
		/* README.md:125 */
	} else if err != nil {
		/* README.md:126 */ panic(err)
		/* README.md:127 */
	}
	/* README.md:133 */ err = channel.Presence.Enter(ctx, "presence data")
	/* README.md:134 */ if err != nil {
		/* README.md:135 */ panic(err)
		/* README.md:136 */
	}
	/* README.md:142 */ err = channel.Presence.EnterClient(ctx, "clientID", "presence data")
	/* README.md:143 */ if err != nil {
		/* README.md:144 */ panic(err)
		/* README.md:145 */
	}
	/* README.md:151 */ // Update also has an UpdateClient variant.
	/* README.md:152 */
	err = channel.Presence.Update(ctx, "new presence data")
	/* README.md:153 */ if err != nil {
		/* README.md:154 */ panic(err)
		/* README.md:155 */
	}
	/* README.md:157 */ // Leave also has an LeaveClient variant.
	/* README.md:158 */
	err = channel.Presence.Leave(ctx, "last presence data")
	/* README.md:159 */ if err != nil {
		/* README.md:160 */ panic(err)
		/* README.md:161 */
	}
	/* README.md:167 */ clients, err := channel.Presence.Get(ctx)
	/* README.md:168 */ if err != nil {
		/* README.md:169 */ panic(err)
		/* README.md:170 */
	}
	/* README.md:172 */ for _, client := range clients {
		/* README.md:173 */ fmt.Println("Present client:", client)
		/* README.md:174 */
	}
	/* README.md:180 */ unsubscribe, err = channel.Presence.SubscribeAll(ctx, func(msg *ably.PresenceMessage) {
		/* README.md:181 */ fmt.Printf("Presence event: action=%v data=%v", msg.Action, msg.Data)
		/* README.md:182 */
	})
	/* README.md:183 */ if err != nil {
		/* README.md:184 */ panic(err)
		/* README.md:185 */
	}
	/* README.md:189 */ unsubscribe()
	/* README.md:195 */ unsubscribe, err = channel.Presence.Subscribe(ctx, ably.PresenceActionEnter, func(msg *ably.PresenceMessage) {
		/* README.md:196 */ fmt.Printf("Presence event: action=%v data=%v", msg.Action, msg.Data)
		/* README.md:197 */
	})
	/* README.md:198 */ if err != nil {
		/* README.md:199 */ panic(err)
		/* README.md:200 */
	}
	/* README.md:204 */ unsubscribe()
	/* README.md:214 */ {
		/* README.md:218 */ client, err := ably.NewREST(ably.WithKey(app.Key()), ably.WithEnvironment(app.Environment), ably.WithUseBinaryProtocol(!ablytest.NoBinaryProtocol), ably.WithClientID("clientID"))
		/* README.md:219 */ if err != nil {
			/* README.md:220 */ panic(err)
			/* README.md:221 */
		}
		/* README.md:223 */ channel := client.Channels.Get("test")
		/* README.md:229 */ err = channel.Publish(ctx, "HelloEvent", "Hello!")
		/* README.md:230 */ if err != nil {
			/* README.md:231 */ panic(err)
			/* README.md:232 */
		}
		/* README.md:234 */ // You can also publish a batch of messages in a single request.
		/* README.md:235 */
		err = channel.PublishMultiple(ctx, []*ably.Message{
			/* README.md:236 */ {Name: "HelloEvent", Data: "Hello!"},
			/* README.md:237 */ {Name: "ByeEvent", Data: "Bye!"},
			/* README.md:238 */})
		/* README.md:239 */ if err != nil {
			/* README.md:240 */ panic(err)
			/* README.md:241 */
		}
		/* README.md:247 */ {
			/* README.md:251 */ pages, err := channel.History().Pages(ctx)
			/* README.md:252 */ if err != nil {
				/* README.md:253 */ panic(err)
				/* README.md:254 */
			}
			/* README.md:255 */ for pages.Next(ctx) {
				/* README.md:256 */ for _, message := range pages.Items() {
					/* README.md:257 */ fmt.Println(message)
					/* README.md:258 */
				}
				/* README.md:259 */
			}
			/* README.md:260 */ if err := pages.Err(); err != nil {
				/* README.md:261 */ panic(err)
				/* README.md:262 */
			}
			/* README.md:267 */
		}
		/* README.md:273 */ {
			/* README.md:277 */ page, err := channel.Presence.Get(ctx, nil)
			/* README.md:278 */ for ; err == nil && page != nil; page, err = page.Next(ctx) {
				/* README.md:279 */ for _, presence := range page.PresenceMessages() {
					/* README.md:280 */ fmt.Println(presence)
					/* README.md:281 */
				}
				/* README.md:282 */
			}
			/* README.md:283 */ if err != nil {
				/* README.md:284 */ panic(err)
				/* README.md:285 */
			}
			/* README.md:289 */
		}
		/* README.md:295 */ {
			/* README.md:299 */ pages, err := channel.Presence.History().Pages(ctx)
			/* README.md:300 */ if err != nil {
				/* README.md:301 */ panic(err)
				/* README.md:302 */
			}
			/* README.md:303 */ for pages.Next(ctx) {
				/* README.md:304 */ for _, presence := range pages.Items() {
					/* README.md:305 */ fmt.Println(presence)
					/* README.md:306 */
				}
				/* README.md:307 */
			}
			/* README.md:308 */ if err := pages.Err(); err != nil {
				/* README.md:309 */ panic(err)
				/* README.md:310 */
			}
			/* README.md:314 */
		}
		/* README.md:320 */ {
			/* README.md:324 */ pages, err := client.Stats().Pages(ctx)
			/* README.md:325 */ if err != nil {
				/* README.md:326 */ panic(err)
				/* README.md:327 */
			}
			/* README.md:328 */ for pages.Next(ctx) {
				/* README.md:329 */ for _, stat := range pages.Items() {
					/* README.md:330 */ fmt.Println(stat)
					/* README.md:331 */
				}
				/* README.md:332 */
			}
			/* README.md:333 */ if err := pages.Err(); err != nil {
				/* README.md:334 */ panic(err)
				/* README.md:335 */
			}
			/* README.md:339 */
		}
		/* README.md:343 */
	}
}
