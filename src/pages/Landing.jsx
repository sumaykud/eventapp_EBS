import React from 'react';

const Landing = () => {
  return (
    <div className="min-h-screen bg-white">
      {/* Top Navigation */}
<div className="w-full">
  <nav className="bg-white sticky top-0 z-50 w-full">
    <div className="border-b border-gray-200 w-full"></div> 
  </nav>

  {/* Container for the content */}
  <nav className="bg-white sticky top-0 z-50">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex items-center justify-between h-16">
        {/* Logo */}
        <div className="flex-shrink-0">
          <span className="text-gray-700 font-bold text-lg">Logo</span>
        </div>

        {/* Navigation Items */}
        <div className="flex items-center space-x-6 sm:space-x-8 lg:space-x-8">
          <a href="#home" className="text-gray-700 hover:text-indigo-600 font-medium">Home</a>
          <a href="#jadwal" className="text-gray-700 hover:text-indigo-600 font-medium">Jadwal</a>
          <a href="#modul" className="text-gray-700 hover:text-indigo-600 font-medium">Modul</a>
          <button className="bg-white border border-indigo-600 text-indigo-600 hover:bg-indigo-600 hover:text-white px-6 py-2 rounded-full text-sm font-medium transition-colors duration-200">
            Login
          </button>
        </div>
      </div>
    </div>
  </nav>
</div>


      {/* Hero Section */}
      <section id="home" className="bg-white py-12 lg:py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12 items-center min-h-[500px]">
            {/* Text Content */}
            <div className="space-y-6 lg:space-y-8">
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold leading-tight text-gray-900">
                Selamat datang di Evangalish Bible Study. 
              </h1>
              <p className="text-base sm:text-lg text-gray-600 leading-relaxed max-w-lg">
                Pelajari makna dan tujuan dari kekristenan dalam 
              </p>
              <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 pt-2">
                <a
                  href="#register"
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 sm:px-8 py-3 rounded-full font-semibold text-sm sm:text-base transition-all duration-200 text-center inline-block"
                >
                  Register Now
                </a>
                <a
                  href="#learn-more"
                  className="border-2 border-indigo-600 text-indigo-600 hover:bg-indigo-600 hover:text-white px-6 sm:px-8 py-3 rounded-full font-semibold text-sm sm:text-base transition-all duration-200 text-center inline-block"
                >
                  Learn More
                </a>
              </div>
            </div>
            {/* Banner/Image */}
            <div className="relative lg:order-last">
              <div className="bg-gray-200 rounded-2xl p-6 sm:p-8 h-80 sm:h-96 flex items-center justify-center">
                <span className="text-center text-gray-500">Event Banner</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-800 text-white w-full">
        <div className="px-4 sm:px-6 lg:px-8 py-12">
          <div className="text-center">
            <p className="text-gray-400">&copy; 2025 EBS. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
