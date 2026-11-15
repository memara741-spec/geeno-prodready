"use client";

import { useState } from "react";

type Message = { role: "user" | "assistant"; content: string };

export function Chat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");

  const send = async () => {
    const next = [...messages, { role: "user" as const, content: input }];
    setMessages(next);
    const res = await fetch("/api/chat", {
      method: "POST",
      body: JSON.stringify({ messages: next, model: "gpt-4o", system: "You are a helpful assistant." }),
    });
    const data = await res.json();
    setMessages([...next, { role: "assistant", content: data.reply }]);
  };

  return (
    <div>
      {messages.map((message, i) => (
        <div key={i} className={message.role} dangerouslySetInnerHTML={{ __html: message.content }} />
      ))}
      <input aria-label="Message" value={input} onChange={(e) => setInput(e.target.value)} />
      <button onClick={send}>Send</button>
    </div>
  );
}
