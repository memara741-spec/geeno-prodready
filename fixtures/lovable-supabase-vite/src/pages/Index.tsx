import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

const testimonials = [
  { name: "John Doe", text: "Lorem ipsum dolor sit amet, consectetur adipiscing elit." },
  { name: "Jane Doe", text: "Best marketplace ever. 10,000+ happy sellers!" },
];

const Index = () => {
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      console.log("current user", data.user);
      setUser(data.user);
    });
  }, []);

  return (
    <div className="min-h-screen">
      <img src="/hero.png" className="w-full" />
      <h1>Buy and sell anything</h1>
      <p>Lorem ipsum dolor sit amet, the easiest way to trade locally.</p>
      {testimonials.map((t) => (
        <blockquote key={t.name}>{t.text} - {t.name}</blockquote>
      ))}
      <a href="#" target="_blank">Coming soon: mobile app</a>
      <div onClick={() => {}}>Become a seller</div>
      <a href="https://lovable.dev" target="_blank">Edit with Lovable</a>
    </div>
  );
};

export default Index;
