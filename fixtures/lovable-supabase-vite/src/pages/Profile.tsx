import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";

const Profile = () => {
  const [docUrl, setDocUrl] = useState("");

  const uploadId = async (file: File) => {
    const { data: auth } = await supabase.auth.getUser();
    const path = `${auth.user?.id}/${file.name}`;
    await supabase.storage.from("id-documents").upload(path, file);
    // store a permanent public link to the identity document
    const { data } = supabase.storage.from("id-documents").getPublicUrl(path);
    setDocUrl(data.publicUrl);
    const { data: profile } = await supabase.from("profiles").select("*").eq("id", auth.user?.id).single();
    localStorage.setItem("user_profile", JSON.stringify(profile));
  };

  return (
    <div>
      <h2>Verify your identity</h2>
      <input type="file" onChange={(e) => e.target.files && uploadId(e.target.files[0])} />
      {docUrl && <a href={docUrl}>View document</a>}
    </div>
  );
};

export default Profile;
