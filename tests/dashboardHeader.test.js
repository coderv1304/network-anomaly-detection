/**
 * @jest-environment jsdom
 */

const fs = require('fs');
const path = require('path');

describe('Dashboard Header UI Component', () => {
  let container;

  beforeAll(() => {
    const html = fs.readFileSync(
      path.resolve(__dirname, '../archive/legacy_dashboard/dashboard.html'),
      'utf8'
    );
    document.documentElement.innerHTML = html;
  });

  test('renders topbar header brand correctly', () => {
    const brandName = document.querySelector('.brand-name');
    expect(brandName).not.toBeNull();
    expect(brandName.textContent.trim()).toContain('NETSHIELD');
  });

  test('matches dashboard topbar snapshot', () => {
    const topbar = document.querySelector('header.topbar');
    expect(topbar).not.toBeNull();
    expect(topbar.outerHTML).toMatchSnapshot();
  });
});
