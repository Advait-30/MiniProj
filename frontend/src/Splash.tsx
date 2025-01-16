import React from 'react';
import { Link } from 'react-router-dom';

const Splash: React.FC = () => {
  return (
    <div className="App">
      <header className="App-header">
        <h1>Healthcare WBAN</h1>
        <p>Secure Authentication</p>
        <Link to="/login">
          <button>Go to Login</button>
        </Link>
      </header>
    </div>
  );
};

export default Splash; 