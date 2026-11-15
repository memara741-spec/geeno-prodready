import { useEffect, useState } from "react";
import _ from "lodash";
import moment from "moment";
import { supabase } from "@/integrations/supabase/client";
import { describeListing } from "@/lib/ai";

const Listings = () => {
  const [listings, setListings] = useState<any[]>([]);
  const [title, setTitle] = useState("");

  useEffect(() => {
    supabase.from("listings").select("*").then(({ data }) => setListings(_.sortBy(data || [], "created_at")));
  }, []);

  const create = async () => {
    const { data: auth } = await supabase.auth.getUser();
    const description = await describeListing(title);
    await supabase.from("listings").insert({ title, description, user_id: auth.user?.id, price: 9.99 });
  };

  return (
    <div>
      <input value={title} onChange={(e) => setTitle(e.target.value)} />
      <button onClick={create}>Create listing</button>
      {listings.map((l) => (
        <div key={l.id}>{l.title} - {moment(l.created_at).fromNow()}</div>
      ))}
    </div>
  );
};

export default Listings;
