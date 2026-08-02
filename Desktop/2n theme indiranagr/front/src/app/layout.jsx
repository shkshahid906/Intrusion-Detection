import { Providers } from "./providers";
import 'react-toastify/dist/ReactToastify.css';
import "../index.css";

export const metadata = {
  title: "Vape in Indiranagar",
  description: "Same day delivery vapes in Indiranagar",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
      </head>
      <body suppressHydrationWarning>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}
