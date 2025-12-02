import React from 'react';
import styled from 'styled-components';

interface LogoutCardProps {
  onLogout?: () => void;
}

const LogoutCard: React.FC<LogoutCardProps> = ({ onLogout }) => {
  const handleMouseDown = (e: React.MouseEvent) => {
    const target = e.currentTarget as HTMLElement;
    const before = target.querySelector('.delete-before') as HTMLElement;

    if (before) {
      before.style.animation = 'delete 2.5s ease-in-out forwards 0.2s';

      setTimeout(() => {
        onLogout?.();
      }, 2700);
    }
  };

  const handleMouseUp = (e: React.MouseEvent) => {
    const target = e.currentTarget as HTMLElement;
    const before = target.querySelector('.delete-before') as HTMLElement;

    if (before) {
      before.style.animation = '';
    }
  };

  const handleMouseLeave = (e: React.MouseEvent) => {
    const target = e.currentTarget as HTMLElement;
    const before = target.querySelector('.delete-before') as HTMLElement;

    if (before) {
      before.style.animation = '';
    }
  };

  return (
    <StyledWrapper>
      <div className="card">
        <ul className="list">
          <li
            className="item delete"
            onMouseDown={handleMouseDown}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseLeave}
          >
            <div className="delete-before"></div>
            <span className="label">Logout</span>
            <span className="label action">Hold to Confirm</span>
            <svg width={22} height={22} viewBox="0 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg" transform="rotate(0 0 0)">
              <path d="M11.5781 2.5C10.3355 2.5 9.32812 3.50736 9.32812 4.75V6.6285C9.44877 6.70925 9.56333 6.80292 9.66985 6.90952L10.8281 8.06853V4.75C10.8281 4.33579 11.1639 4 11.5781 4H17.5781C17.9923 4 18.3281 4.33579 18.3281 4.75V20.25C18.3281 20.6642 17.9923 21 17.5781 21H11.5781C11.1639 21 10.8281 20.6642 10.8281 20.25V16.9314L9.6699 18.0904C9.56336 18.197 9.44879 18.2907 9.32812 18.3715V20.25C9.32812 21.4926 10.3355 22.5 11.5781 22.5H17.5781C18.8208 22.5 19.8281 21.4926 19.8281 20.25V4.75C19.8281 3.50736 18.8208 2.5 17.5781 2.5H11.5781Z" fill="#343C54" />
              <path d="M3.57812 12.5C3.57812 12.7259 3.67796 12.9284 3.83591 13.0659L7.79738 17.0301C8.09017 17.3231 8.56504 17.3233 8.85804 17.0305C9.15104 16.7377 9.1512 16.2629 8.85841 15.9699L6.14046 13.25L12.0781 13.25C12.4923 13.25 12.8281 12.9142 12.8281 12.5C12.8281 12.0858 12.4923 11.75 12.0781 11.75L6.14028 11.75L8.85839 9.03016C9.15119 8.73718 9.15104 8.2623 8.85806 7.9695C8.56507 7.6767 8.0902 7.67685 7.7974 7.96984L3.83388 11.9359C3.67711 12.0733 3.57812 12.2751 3.57812 12.5Z" fill="#343C54" />
            </svg>
          </li>
        </ul>
      </div>
    </StyledWrapper>
  );
}

const StyledWrapper = styled.div`
  .card {
    background: #222222;
    width: 195px;
    border: 2px solid #313131;
    border-radius: 10px;
    padding: 3px 4px;

    .list {
      color: #e9e9e9;
      list-style-type: none;
      display: flex;
      flex-direction: column;
      gap: 3px;
      margin: 0;
      padding: 0;

      .item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        transition: all 0.3s ease;
        padding: 6px 8px;
        border-radius: 5px;
        cursor: pointer;
        position: relative;
        overflow: hidden;
        user-select: none;

        svg {
          z-index: 1;
          transition: all 0.3s ease;
        }
        &:hover {
          background: #333333;
        }

        .label {
          font-weight: 400;
          transition: all 0.2s ease;
          z-index: 1;
        }

        &.delete {
          color: #e3616a;
          position: relative;
          &:hover {
            background: #6b2c2b;
          }

          .label {
            transform: translateY(0);
          }

          &:active {
            .label {
              opacity: 0;
              visibility: hidden;
              transform: translateY(100%) translateX(-15px) scale(0.8);
            }
            .action {
              opacity: 1;
              visibility: visible;
              transform: translateY(0);
            }
          }

          .action {
            position: absolute;
            opacity: 0;
            visibility: hidden;
            transform: translateY(-50%) translateX(-15px) scale(0.8);
          }

          .delete-before {
            position: absolute;
            background-color: #89302d;
            left: 0;
            top: 0;
            height: 100%;
            width: 0%;
          }
        }
      }
    }
  }

  @keyframes delete {
    from {
      width: 0%;
    }

    to {
      width: 100%;
    }
  }
`;

export default LogoutCard;
