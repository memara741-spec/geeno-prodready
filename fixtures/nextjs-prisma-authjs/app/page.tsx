import dayjs from "dayjs";

export default function Home() {
  return <main><h1>TeamTasks</h1><p>Today is {dayjs().format("dddd")}</p></main>;
}
