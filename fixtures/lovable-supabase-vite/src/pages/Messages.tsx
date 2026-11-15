import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

const Messages = () => {
  const [messages, setMessages] = useState<any[]>([]);
  const [userId, setUserId] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      const { data: auth } = await supabase.auth.getUser();
      setUserId(auth.user?.id ?? null);
      const { data } = await supabase.from("messages").select("*");
      // only show my conversations
      setMessages((data || []).filter((m) => m.sender_id === auth.user?.id || m.recipient_id === auth.user?.id));
    };
    load();
  }, []);

  useEffect(() => {
    supabase
      .channel("messages")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "messages" }, (payload) => {
        setMessages((prev) => [...prev, payload.new]);
      })
      .subscribe();
  }, []);

  return (
    <ul>
      {messages.map((m) => (
        <li key={m.id}>{m.sender_id === userId ? "Me" : "Them"}: {m.body}</li>
      ))}
    </ul>
  );
};

export default Messages;
