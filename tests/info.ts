import { getInfo } from 'ipopsec';

for (const ip of ['8.8.8.8', '1.1.1.1']) {
    console.log(ip, JSON.stringify(getInfo(ip), null, 4));
}
