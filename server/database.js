import { promises as fs } from 'fs';
import path from 'path'; 

const DB_FILE_PATH = path.join(process.cwd(), 'user_database.json');
export const userDatabase = new Map();

export async function loadUserDatabase() {
	try {
		const data = await fs.readFile(DB_FILE_PATH, 'utf8');
		const parsedData = JSON.parse(data);
		for (const [username, passwordHash] of Object.entries(parsedData)) {
			userDatabase.set(username, passwordHash);
		}
		console.log(`User database loaded from ${DB_FILE_PATH}`);
	} catch (error) {
		if (error.code === 'ENOENT') {
			console.log('User database file not found. Initializing an empty database.');
			await saveUserDatabase();
		} else {
			console.error('Error loading user database:', error);
		}
	}
}

export async function saveUserDatabase() {
	try {
		const dataToSave = Object.fromEntries(userDatabase);
		await fs.writeFile(DB_FILE_PATH, JSON.stringify(dataToSave, null, 2), 'utf8');
		console.log(`User database saved to ${DB_FILE_PATH}`);
	} catch (error) {
		console.error('Error saving user database:', error);
	}
}
