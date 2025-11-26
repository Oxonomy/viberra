import React, { useState, useEffect } from 'react';
import {
  Terminal, Lock, Smartphone, Zap, Globe, Shield, Copy, Check,
  EyeOff, KeyRound, Network, ShieldCheck, Fingerprint, SquareTerminal
} from 'lucide-react';
import { Link } from 'react-router-dom';

export default function LandingPage() {
  return (
    <div className="min-h-screen w-full">
      <section className="relative min-h-screen flex flex-col items-center justify-center px-4 py-20 scan-lines">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_hsl(142_76%_56%/0.03)_0%,_transparent_70%)]"></div>

        <div className="relative z-10 text-center mb-12 max-w-4xl mx-auto">
          <h1 className="mb-6">
            <pre className="text-green-600 text-glow font-mono
           text-logo-xs sm:text-logo-sm md:text-logo-md lg:text-logo-lg
           overflow-x-auto px-2 sm:px-4 py-2 sm:py-4">
{`██╗   ██╗██╗██████╗ ███████╗██████╗ ██████╗  █████╗
 ██║   ██║██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██║██████╔╝█████╗  ██████╔╝██████╔╝███████║
 ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══██║
  ╚████╔╝ ██║██████╔╝███████╗██║  ██║██║  ██║██║  ██║
   ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝`}
            </pre>
          </h1>

          <p className="text-lg sm:text-xl md:text-2xl text-zinc-400 mb-4 font-mono">
            CLI agent in Your Pocket
          </p>

          <p className="text-sm sm:text-base md:text-lg text-zinc-400/80 mb-12 max-w-2xl mx-auto leading-relaxed">
            Securely access your CLI agents from anywhere. Vibe coding meets encrypted mobility — your terminal.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center mb-16">
            <Link
              to="/app"
              className="inline-flex items-center justify-center gap-2 bg-green-600 text-white hover:shadow-[0_0_25px_hsl(142_76%_56%/0.6)] hover:scale-105 transition-all duration-300 h-12 px-6 sm:px-8 text-sm sm:text-base font-medium rounded-lg"
            >
              Connect to Agent
            </Link>
            <button
              onClick={() => document.getElementById('getting-started')?.scrollIntoView({ behavior: 'smooth' })}
              className="inline-flex items-center justify-center gap-2 bg-transparent border border-green-600 text-green-600 hover:bg-green-600/10 hover:shadow-[0_0_20px_hsl(142_76%_56%/0.4)] transition-all duration-300 h-12 px-6 sm:px-8 text-sm sm:text-base font-medium rounded-lg"
            >
              Get Started
            </button>
          </div>
        </div>

        {/* P2P Connection Demo */}
        <P2PConnectionDemo />
      </section>

      <section className="px-2 py-16 relative">
        <CodeAnywhereSection />
      </section>

      {/* Getting Started Section */}
      <section id="getting-started" className="px-4 py-16 sm:py-20 relative animate-fade-up">
        <GettingStartedSection />
      </section>

      {/* Zero-Trust P2P Security Block */}
      <section id="zero-trust-p2p" className="px-4 py-16 sm:py-20 relative animate-fade-up">
        <ZeroTrustP2PBlock />
      </section>

      <section className="px-4 py-16 sm:py-20 relative">
        <div className="w-full max-w-6xl mx-auto">
          <div className="text-center mb-12 sm:mb-16">
            <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white mb-4">
              Built for Mobile Hackers
            </h2>
            <p className="text-sm sm:text-base text-zinc-400 max-w-2xl mx-auto">
              Powerful features designed for developers who refuse to be tethered to a desk
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <FeatureCard
              icon={<Lock className="w-6 h-6 text-green-600" />}
              title="End-to-End Encrypted"
              description="Military-grade encryption ensures your sessions stay private. P2P WebRTC means no middleman, no logs."
            />
            <FeatureCard
              icon={<Smartphone className="w-6 h-6 text-green-600" />}
              title="Mobile-First CLI"
              description="Optimized touch interface with smart autocomplete. Terminal power, pocket-sized."
            />
            <FeatureCard
              icon={<Zap className="w-6 h-6 text-green-600" />}
              title="Instant Connection"
              description="Sub-second handshake. Your agent is always ready, just a tap away."
            />
            <FeatureCard
              icon={<Globe className="w-6 h-6 text-green-600" />}
              title="Truly Remote"
              description="Coffee shop, subway, mountaintop — if you have signal, you have access."
            />
            <FeatureCard
              icon={<Shield className="w-6 h-6 text-green-600" />}
              title="Zero Trust Security"
              description="Cryptographic keypair authentication. No passwords, no compromise."
            />
            <FeatureCard
              icon={<Terminal className="w-6 h-6 text-green-600" />}
              title="Full Shell Access"
              description="Not a toy. Full bash/zsh support with all your favorite tools."
            />
          </div>
        </div>
      </section>

      <section className="px-4 py-16 sm:py-20 relative">
        <div className="w-full max-w-4xl mx-auto text-center border border-green-600 bg-zinc-950 p-6 sm:p-12 rounded-lg">
          <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white mb-4">
            Ready for vibe coding?
          </h2>
          <p className="text-sm sm:text-base text-zinc-400 mb-8 max-w-2xl mx-auto">
            Install the agent, connect your device, and never lose access to your terminal again.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center">
            <Link
              to="/app"
              className="inline-flex items-center justify-center gap-2 bg-transparent border border-green-600 text-green-600 hover:bg-green-600/10 hover:shadow-[0_0_20px_hsl(142_76%_56%/0.4)] transition-all duration-300 h-12 px-6 sm:px-8 text-sm sm:text-base font-medium rounded-lg"
            >
              Connect to Agent
            </Link>
            <button
              onClick={() => document.getElementById('getting-started')?.scrollIntoView({ behavior: 'smooth' })}
              className="inline-flex items-center justify-center gap-2 bg-green-600 text-white hover:shadow-[0_0_25px_hsl(142_76%_56%/0.6)] hover:scale-105 transition-all duration-300 h-12 px-6 sm:px-8 text-sm sm:text-base font-medium rounded-lg"
            >
              Get Started
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800 px-4 py-8">
        <div className="w-full max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4 text-xs sm:text-sm text-zinc-400">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-green-600" />
            <span className="font-mono">VIBERRA © 2025</span>
          </div>

          <div className="flex gap-6">
            <a href="#" className="hover:text-green-600 transition-colors">Docs</a>
            <a href="#" className="hover:text-green-600 transition-colors">GitHub</a>
            <a href="#" className="hover:text-green-600 transition-colors">Discord</a>
            <a href="#" className="hover:text-green-600 transition-colors">Privacy</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

// Command Block Component (reusable)
function CommandBlock({ command }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="w-full w-64 sm:w-72">
      <div className="border border-green-600 bg-zinc-800 shadow-[0_0_20px_hsl(142_76%_56%/0.3)] rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 bg-zinc-900">
          <code className="text-white font-mono text-sm sm:text-base font-medium tracking-tight select-all">
            {command}
          </code>
          <button
            onClick={handleCopy}
            className={`ml-3 p-2 hover:bg-green-600/10 transition-all duration-200 ${
              copied ? 'animate-pulse' : ''
            }`}
            aria-label="Copy command"
          >
            {copied ? (
              <Check className="w-4 h-4 text-green-600" />
            ) : (
              <Copy className="w-4 h-4 text-green-600" />
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

function StepsColumn() {
  return (
      <div className="relative w-full max-w-md">
        <StepItem step="1" title="Install">
          <CommandBlock command="npm i viberra" />
        </StepItem>

        <StepItem step="2" title="Launch">
          <div className="w-64 sm:w-72 grid grid-cols-1 gap-2>">
            <CommandBlock command="vibe -m claude" />
            <div className="mt-4 w-full border border-green-600 bg-neutral-950 scan-lines overflow-hidden shadow-[0_0_30px_hsl(142_76%_56%/0.2)] rounded-lg">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-zinc-800 bg-zinc-900">
            <span className="text-xs text-zinc-400 ml-2 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-green-600" />
              viberra
            </span>
                <div className="ml-auto flex gap-2">
                  <div className="w-3 h-3 rounded-full bg-green-600 animate-glow-pulse"></div>
                </div>
              </div>
              <div className="relative bg-black aspect-square overflow-hidden">
                <img
                    src="/media/demo-terminal.png"
                    alt="Terminal session"
                    className="absolute inset-0 w-full h-full object-contain"
                />
              </div>
            </div>
          </div>
        </StepItem>
      </div>
  );
}

function StepItem({
                    step,
                    title,
                    children
                  }) {
  return (
      <div className="relative flex flex-col items-center pb-8 last:pb-0">
        <div className="flex items-center gap-2 mb-3">
          <div className="flex items-center justify-center w-6 h-6 rounded-full bg-green-600 text-black font-mono font-bold text-xs sm:text-sm">
            <span>{step}</span>
          </div>
          <span className="font-mono text-base sm:text-lg text-white">
          {title}
        </span>
        </div>

        <div className="flex w-64 sm:w-72">
          {children}
        </div>
      </div>
  );
}



function P2PConnectionDemo() {
  return (
      <div className="relative z-10 w-full">
        <div className="w-full max-w-6xl mx-auto px-4">
          {/* Main container with flex layout */}
          <div className="flex flex-col lg:flex-row items-center justify-center">

            {/* Steps column (Desktop) - Left side */}
            <div className="w-full lg:w-auto flex justify-center">
              <StepsColumn />
            </div>

            {/* Connection visualization - Center */}
            <div className="relative flex items-center justify-center lg:w-1/4 w-full h-24 lg:h-auto">
              {/* Horizontal connection line for desktop, vertical for mobile */}
              <svg
                  className="absolute inset-0 w-full h-full hidden lg:block"
                  viewBox="0 0 100 100"
                  preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="rgb(22, 163, 74)" stopOpacity="0.2">
                      <animate
                          attributeName="stop-opacity"
                          values="0.2;0.8;0.2"
                          dur="2s"
                          repeatCount="indefinite"
                      />
                    </stop>
                    <stop offset="50%" stopColor="rgb(22, 163, 74)" stopOpacity="0.8">
                      <animate
                          attributeName="stop-opacity"
                          values="0.8;0.3;0.8"
                          dur="2s"
                          repeatCount="indefinite"
                      />
                    </stop>
                    <stop offset="100%" stopColor="rgb(22, 163, 74)" stopOpacity="0.2">
                      <animate
                          attributeName="stop-opacity"
                          values="0.2;0.8;0.2"
                          dur="2s"
                          repeatCount="indefinite"
                      />
                    </stop>
                  </linearGradient>
                </defs>
                <line x1="0" y1="50" x2="100" y2="50" stroke="url(#lineGradient)" strokeWidth="2" />
              </svg>

              {/* Vertical line for mobile */}
              <svg
                  className="absolute inset-0 w-full h-full lg:hidden"
                  viewBox="0 0 100 100"
                  preserveAspectRatio="none"
              >
                <line
                    x1="50"
                    y1="0"
                    x2="50"
                    y2="100"
                    stroke="url(#lineGradient)"
                    strokeWidth="2"
                />
              </svg>

              {/* Animated particles flowing both directions */}
              <div className="absolute inset-0 overflow-hidden">
                {/* Particles left to right (encryption) */}
                <div className="particle particle-1"></div>
                <div className="particle particle-2"></div>
                <div className="particle particle-3"></div>

                {/* Particles right to left (decryption) */}
                <div className="particle-reverse particle-reverse-1"></div>
                <div className="particle-reverse particle-reverse-2"></div>
                <div className="particle-reverse particle-reverse-3"></div>
              </div>

              {/* Central lock icon with glow */}
              <div
                onClick={() => document.getElementById('zero-trust-p2p')?.scrollIntoView({ behavior: 'smooth' })}
                className="relative z-10 p-3 sm:p-4 bg-zinc-950 border-2 border-green-600 rounded-full shadow-[0_0_30px_hsl(142_76%_56%/0.4)] cursor-pointer hover:shadow-[0_0_40px_hsl(142_76%_56%/0.6)] transition-shadow duration-300"
              >
                <Lock className="w-5 h-5 sm:w-6 sm:h-6 text-green-600" />
              </div>
            </div>

            {/* Mobile Device - Right side (unchanged) */}
            <StepItem step="3" title="Connect">
              <div className="flex justify-center">
                {/* Mobile phone frame */}
                <Link to="/app" className="relative w-64 sm:w-72 hover:shadow-[0_0_40px_hsl(142_76%_56%/0.4)] transition-shadow duration-300 rounded-[2.5rem]">
                  {/* Phone body */}
                  <div className="border-[8px] border-zinc-800 rounded-[2.5rem] bg-black overflow-hidden shadow-[0_0_30px_hsl(142_76%_56%/0.2)]">
                    {/* Notch */}
                    <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-6 bg-zinc-800 rounded-b-2xl z-20"></div>

                    {/* Screen with border glow */}
                    <div className="relative border border-green-600/30">
                      <img
                          src="/media/demo-mobile.png"
                          alt="Mobile terminal"
                          className="w-full aspect-[1/2] object-contain"
                      />
                    </div>

                    {/* Home indicator / unlock button */}
                    <div className="absolute bottom-2 left-1/2 -translate-x-1/2 w-32 h-1 bg-zinc-700 rounded-full"></div>
                  </div>
                </Link>
              </div>
            </StepItem>

          </div>
        </div>
      </div>
  );
}


function FeatureCard({ icon, title, description }) {
  return (
    <div className="terminal-border bg-zinc-950 p-4 sm:p-6 hover:shadow-[0_0_20px_hsl(142_76%_56%/0.3)] border border-green-600 rounded-lg transition-all duration-300 group">
      <div className="flex items-start gap-3 sm:gap-4">
        <div className="p-2.5 sm:p-3 bg-green-600/10 border border-green-600/30 group-hover:border-green-600 transition-colors flex-shrink-0">
          {icon}
        </div>
        <div className="flex-1">
          <h3 className="text-base sm:text-lg font-semibold text-white mb-2">{title}</h3>
          <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed">{description}</p>
        </div>
      </div>
    </div>
  );
}

function CodeAnywhereSection() {
  // Media refs
  const mobilePhrasesRef = React.useRef([
    "on the subway",
    "out for coffee",
    "on a walk",
    "even here",
  ]);

  const mobileGifsRef = React.useRef([
    "/media/person-subway-sitting.gif",
    "/media/person-cafe.gif",
    "/media/person-walking-outdoor.gif",
    "/media/person-toilet.gif",
  ]);

  const desktopGifsRef = React.useRef([
    "/media/cli_claude_1.gif",
    "/media/cli_claude_2.gif",
    "/media/cli_gemini_1.gif",
    "/media/cli_aider_0.gif",
  ]);

  const desktopTitlesRef = React.useRef([
    "viberra -m claude",
    "viberra -m claude",
    "viberra -m gemini",
    "viberra -m aider",
  ]);

  const mobileTitlesRef = React.useRef([
    "Ship before the office",
    "Order up — and so is my PR",
    "Sprint planning - literally",
    "Best ideas happen in the shower",
  ]);

  const STRIPES_GIF = "/media/horizontal_stripes.gif";
  const DESKTOP_INITIAL_GIF = "/media/person-desktop-terminal-fast.gif";

  // Timing constants
  const INITIAL_PHASE_MS = 2100;
  const PAUSE_AFTER_INITIAL_MS = 500;
  const TYPE_SPEED = 50;
  const SHOW_MS = 3000;
  const ERASE_SPEED = 12;
  const GAP_MS = 600;

  // State
  const [isInitialPhase, setIsInitialPhase] = useState(true);
  const [isPauseAfterInitial, setIsPauseAfterInitial] = useState(false);
  const [currentPhraseIndex, setCurrentPhraseIndex] = useState(0);
  const [displayedText, setDisplayedText] = useState("");
  const [phase, setPhase] = useState("typing");
  const [isVisible, setIsVisible] = useState(false);
  const sectionRef = React.useRef(null);

  // Intersection Observer for lazy animation start
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !isVisible) {
          setIsVisible(true);
        }
      },
      { threshold: 0.2 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, [isVisible]);

  // Preload all GIFs
  useEffect(() => {
    [
      STRIPES_GIF,
      DESKTOP_INITIAL_GIF,
      ...mobileGifsRef.current,
      ...desktopGifsRef.current,
    ].forEach((src) => {
      const img = new Image();
      img.src = src;
    });
  }, []);

  // Initial phase timer (only start when section is visible)
  useEffect(() => {
    if (!isVisible) return;

    const timer = setTimeout(() => {
      setIsInitialPhase(false);
      setIsPauseAfterInitial(true);
    }, INITIAL_PHASE_MS);

    return () => clearTimeout(timer);
  }, [isVisible]);

  // Pause timer after initial phase
  useEffect(() => {
    if (!isInitialPhase && isPauseAfterInitial) {
      const timer = setTimeout(() => {
        setIsPauseAfterInitial(false);
      }, PAUSE_AFTER_INITIAL_MS);

      return () => clearTimeout(timer);
    }
  }, [isInitialPhase, isPauseAfterInitial]);

  // Typewriter animation
  useEffect(() => {
    if (isInitialPhase || isPauseAfterInitial) return;

    const phrases = mobilePhrasesRef.current;
    const currentPhrase = phrases[currentPhraseIndex];
    let t;

    if (phase === "typing") {
      if (displayedText.length < currentPhrase.length) {
        t = setTimeout(() => {
          setDisplayedText(currentPhrase.slice(0, displayedText.length + 1));
        }, TYPE_SPEED);
      } else {
        setPhase("show");
      }
    } else if (phase === "show") {
      t = setTimeout(() => {
        setPhase("erase");
      }, SHOW_MS);
    } else if (phase === "erase") {
      if (displayedText.length > 0) {
        t = setTimeout(() => {
          setDisplayedText((s) => s.slice(0, -1));
        }, ERASE_SPEED);
      } else {
        setPhase("gap");
      }
    }  else if (phase === "gap") {
      t = setTimeout(() => {
        setCurrentPhraseIndex(
            (prev) => (prev + 1) % mobilePhrasesRef.current.length
        );
        setPhase("gapMid");
      }, GAP_MS / 2);
    } else if (phase === "gapMid") {
      t = setTimeout(() => {
        setPhase("typing");
      }, GAP_MS / 2);
    }

    return () => clearTimeout(t);
  }, [isInitialPhase, isPauseAfterInitial, phase, displayedText, currentPhraseIndex]);

  const mobilePhrases = mobilePhrasesRef.current;
  const mobileGifs = mobileGifsRef.current;
  const desktopGifs = desktopGifsRef.current;
  const desktopTitles = desktopTitlesRef.current;
  const mobileTitles = mobileTitlesRef.current;

  const stripesVisible = phase === "typing" || phase === "gap" || phase === "gapMid";
  const isInCycle = !isInitialPhase && !isPauseAfterInitial;

  // Show titles only during show and erase phases
  const showTitle = isInCycle && (phase === "show" || phase === "erase");

  // Determine which GIFs to show
  const desktopGif = isInitialPhase
    ? DESKTOP_INITIAL_GIF
    : desktopGifs[currentPhraseIndex];
  const mobileGif = mobileGifs[currentPhraseIndex];

  // Determine which titles to show
  const desktopTitle = showTitle ? desktopTitles[currentPhraseIndex] : "";
  const mobileTitle = showTitle ? mobileTitles[currentPhraseIndex] : "";

  // Desktop block visibility logic
  const desktopShowStripes = isPauseAfterInitial || (isInCycle && stripesVisible);
  const desktopHideMainGif = isPauseAfterInitial || (isInCycle && phase === "typing");

  // Mobile block visibility logic
  const mobileShowStripes = isInitialPhase || isPauseAfterInitial || (isInCycle && stripesVisible);
  const mobileHideMainGif = isInitialPhase || isPauseAfterInitial || (isInCycle && phase === "typing");

  return (
    <div ref={sectionRef} className="w-full max-w-6xl mx-auto px-4 space-y-12">
      {/* Desktop Block: video left, text right */}
      <div className="flex flex-col-reverse lg:flex-row items-center gap-4 sm:gap-5 lg:gap-12">
        {/* Terminal Window with synchronized stripes */}
        <div className="w-full lg:w-1/2">
          <TerminalWindow
            gif={desktopGif}
            showStripes={desktopShowStripes}
            stripesGif={STRIPES_GIF}
            hideMainGif={desktopHideMainGif}
            title={desktopTitle}
          />
        </div>

        {/* Static Text */}
        <div className="w-full lg:w-1/2 flex flex-col justify-center">
          <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-white text-glow">
            Start at your desk
          </h2>
        </div>
      </div>

      {/* Mobile Block: text left, video right (flex-row-reverse) */}
      <div className="flex flex-col-reverse lg:flex-row-reverse items-center gap-2 sm:gap-3 lg:gap-12">
        {/* Terminal Window with stripes overlay */}
        <div className="w-full lg:w-1/2">
          <TerminalWindow
            gif={mobileGif}
            showStripes={mobileShowStripes}
            stripesGif={STRIPES_GIF}
            hideMainGif={mobileHideMainGif}
            title={mobileTitle}
          />
        </div>

        {/* Typewriter Text */}
        <div className="w-full lg:w-1/2 flex flex-col justify-center">
          <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-white text-glow mb-2 sm:mb-3">
            Keep coding — wherever you are:
          </h2>

          {isInCycle && (
            <div className="text-lg sm:text-2xl md:text-3xl font-mono text-green-600 min-h-[2.5rem] flex items-start">
              <span>&gt; {displayedText}</span>
              <span className="inline-block w-2 h-7 sm:h-8 md:h-10 bg-green-600 ml-1 cursor-blink"></span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Reusable Terminal Window component
function TerminalWindow({ gif, showStripes = false, stripesGif = "", hideMainGif = false, title = "" }) {
  return (
    <div className="border border-green-600 bg-zinc-950 scan-lines overflow-hidden rounded-lg">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800 bg-neutral-950">
        <Terminal className="w-4 h-4 text-green-600" />
        {title && <span className="text-xs text-zinc-400">{title}</span>}
        <div className="ml-auto flex gap-2">
          <div className="w-3 h-3 rounded-full bg-green-600 animate-glow-pulse"></div>
        </div>
      </div>

      <div className="relative w-full bg-black aspect-[16/10] overflow-hidden">
        {/* Main GIF */}
        <img
          src={gif}
          alt="Terminal session"
          className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-500 ${
            hideMainGif ? "opacity-0" : "opacity-100"
          }`}
        />
        {/* Stripes overlay */}
        {stripesGif && (
          <img
            src={stripesGif}
            alt="Typing indicator"
            className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-500 pointer-events-none select-none ${
              showStripes ? "opacity-100" : "opacity-0"
            }`}
          />
        )}
      </div>
    </div>
  );
}

function GettingStartedSection() {
  return (
    <div className="w-full max-w-4xl mx-auto">
      <div className="text-center mb-10 sm:mb-12">
        <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white">
          Getting Started
        </h2>
      </div>

      {/* Dark terminal code block */}
      <div className="border border-green-600 bg-zinc-950 scan-lines overflow-hidden rounded-lg">
        <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 bg-neutral-950">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-green-600" />
            <span className="text-xs text-zinc-400">installation guide</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-green-600 animate-glow-pulse"></div>
          </div>
        </div>

        <div className="relative w-full bg-black p-6 sm:p-8 overflow-auto">
          <pre className="font-mono text-sm sm:text-base whitespace-pre-wrap break-words leading-relaxed">
            <code>
              <span className="text-zinc-500"># Install viberra</span>{'\n'}
              <span className="text-green-500">npm</span> <span className="text-green-400">i</span> <span className="text-purple-400">viberra</span>{'\n\n'}
              <span className="text-zinc-500"># Change directory into your codebase</span>{'\n'}
              <span className="text-green-500">cd</span> <span className="text-blue-400">/to/your/project</span>{'\n\n'}
              <span className="text-zinc-500"># Claude Code CLI</span>{'\n'}
              <span className="text-green-500">vibe</span>{'\n'}
              <span className="text-zinc-500"># or</span>{'\n'}
              <span className="text-green-500">vibe</span> <span className="text-cyan-400">-m</span> <span className="text-white">claude</span>{'\n\n'}
              <span className="text-zinc-500"># Gemini CLI</span>{'\n'}
              <span className="text-green-500">vibe</span> <span className="text-cyan-400">-m</span> <span className="text-white">gemini</span>{'\n\n'}
              <span className="text-zinc-500"># Codex CLI</span>{'\n'}
              <span className="text-green-500">vibe</span> <span className="text-cyan-400">-m</span> <span className="text-white">codex</span>
            </code>
          </pre>
        </div>
      </div>
    </div>
  );
}

function ZeroTrustP2PBlock() {
  return (
    <div className="w-full max-w-6xl mx-auto">
      <div className="text-center mb-10 sm:mb-12">
        <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white">
          Zero-Trust P2P
        </h2>
        <p className="text-xs sm:text-sm text-zinc-400 mt-2">
          server — signaling-only, no access to data
        </p>
      </div>

      <div className="w-full max-w-4xl mx-auto text-center border border-green-600 bg-zinc-950 p-6 sm:p-12 rounded-lg">
        <div className="relative grid grid-cols-1 grid-cols-[max-content_max-content_max-content]  items-stretch justify-center gap-y-6 lg:gap-y-0">
          <EndpointCard
            title="Agent"
            icon={<SquareTerminal className="w-5 h-5 text-green-600" />}
            sub={<span className="text-[10px] text-zinc-500">Ed25519 / X25519</span>}
          />


          <div className="relative">
            <div className="flex flex-col items-center justify-center">
              <div className="mt-8 lg:mt-0 px-3 py-2 rounded-full bg-zinc-950/80 border border-zinc-800 backdrop-blur-sm shadow-[0_0_18px_rgba(16,185,129,0.12)] mb-3">
                <div className="flex items-center gap-2 text-zinc-400 text-xs">
                  <EyeOff className="w-4 h-4 text-zinc-500" />
                  <span className="font-mono">relay only</span>
                </div>
              </div>

              <div className="w-full h-[2px] bg-gradient-to-r from-green-700/20 via-green-500/80 to-green-700/20" />

              <div className="flex flex-wrap items-center justify-center grid grid-cols-2 lg:grid-cols-4 my-3 lg:mx-12 gap-1 px-1 lg:gap-2 lg:px-5">
                <Chip icon={<KeyRound className="w-4 h-4" />} label="ECDH"/>
                <Chip icon={<ShieldCheck className="w-4 h-4" />} label="KDF"/>
                <Chip icon={<Network className="w-4 h-4" />} label="P2P"/>
                <Chip icon={<Lock className="w-4 h-4" />} label="AEAD"/>
              </div>
            </div>
          </div>


          <EndpointCard
            title="Client"
            icon={<Smartphone className="w-5 h-5 text-green-600" />}
            sub={<span className="text-[10px] text-zinc-500">AEAD / counters</span>}
          />
        </div>
        <div className="mt-8 sm:mt-10 flex flex-wrap items-center justify-center gap-2">
          <Pill
            icon={<ShieldCheck className="w-4 h-4" />}
            text="MITM-safe"
          />
          <Pill
            icon={<EyeOff className="w-4 h-4" />}
            text="No content"
          />
          <Pill
            icon={<Lock className="w-4 h-4" />}
            text="Replay-proof"
          />
        </div>
      </div>
    </div>
  );
}

function EndpointCard({ title, icon, sub}) {
  return (
    <div
      className="terminal-border bg-zinc-950 p-2 lg:p-4 max-w-xs rounded-lg text-center border border-green-500/50
       shadow-[0_0_25px_rgba(34,197,94,0.15)] h-full flex flex-col items-center justify-center"
    >
      <div className="flex items-center justify-center gap-2 mb-2">
        {icon}
        <span className="text-sm sm:text-base font-semibold text-white">{title}</span>
      </div>
      <div className="text-xs">{sub}</div>
    </div>
  );
}

function Chip({ icon, label }) {
  return (
    <div
      className="flex items-center gap-1.5 px-2 py-1 rounded-md border border-green-600/30 bg-green-600/5"
    >
      {icon}
      <span className="text-[10px] font-mono text-green-500">{label}</span>
    </div>
  );
}

function Pill({ icon, text }) {
  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-zinc-800 bg-zinc-950"
    >
      {icon}
      <span className="text-xs text-zinc-300">{text}</span>
    </div>
  );
}
